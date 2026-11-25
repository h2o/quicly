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
#ifndef quicly_local_cid_h
#define quicly_local_cid_h

#include "quicly/cid.h"

#ifdef __cplusplus
extern "C" {
#endif

enum en_quicly_local_cid_state_t {
    /**
     * this entry is free for use
     */
    QUICLY_LOCAL_CID_STATE_IDLE,
    /**
     * this entry is to be sent at the next round of send operation
     */
    QUICLY_LOCAL_CID_STATE_PENDING,
    /**
     * this entry has been sent and is waiting for ACK (or to be deemed lost)
     */
    QUICLY_LOCAL_CID_STATE_INFLIGHT,
    /**
     * this CID has been delivered to the remote peer (ACKed) and in use
     */
    QUICLY_LOCAL_CID_STATE_DELIVERED,
};

/**
 * records information for sending NEW_CONNECTION_ID frame
 */
typedef struct st_quicly_local_cid_t {
    enum en_quicly_local_cid_state_t state;
    uint64_t sequence;
    quicly_cid_t cid;
    uint8_t stateless_reset_token[QUICLY_STATELESS_RESET_TOKEN_LEN];
} quicly_local_cid_t;

/**
 * manages a list of connection IDs we issue to the remote peer
 */
typedef struct st_quicly_local_cid_set_t {
    /**
     * Identifier of the connection used by quicly. Three tuple of (node_id, thread_id, master_id) is used to identify the
     * connection. `path_id` is maintained by the "local_cid" module, and used for identifying each CID being issued.
     */
    quicly_cid_plaintext_t plaintext;
    /**
     * storage to retain local CIDs that have been issued and are yet to be retired (unused entries are in IDLE state)
     *
     * Pending CIDs (state == STATE_PENDING) are moved to the front of the array, in the order it was marked as pending.
     * This ensures that pending CIDs are sent in FIFO manner. Order of CIDs with other states is not defined.
     *
     * The array is twice as large as the number of CIDs being issued, so that the CIDs being retired by `retire_prior_to` can be
     * retained until the peer retires them, while the same number of new CIDs are issued.
     */
    quicly_local_cid_t cids[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT * 2];
    quicly_cid_encryptor_t *_encryptor;
    /**
     * value of the Retire Prior To field of the NEW_CONNECTION_ID frames being sent
     */
    uint64_t retire_prior_to;
    /**
     * generation of the key used by `_encryptor` when the CIDs were issued (see `quicly_cid_encryptor_t::get_key_generation`)
     */
    uint64_t key_generation;
} quicly_local_cid_set_t;

/**
 * initialize the structure
 *
 * The set is initialized with one CID (sequence==0 is registered as DELIVERED). If `encryptor` is NULL, the CID is zero-length and
 * no more CIDs are issued.
 */
void quicly_local_cid_init_set(quicly_local_cid_set_t *set, quicly_cid_encryptor_t *encryptor,
                               const quicly_cid_plaintext_t *new_cid);
/**
 * Issues CIDs so that `size` CIDs are available to the peer. Afterwards, the number is retained by issuing a new CID whenever the
 * peer retires one. This function is called once, after initialization. `size` must not exceed
 * QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT.
 *
 * Returns true if there is something to send.
 */
int quicly_local_cid_set_size(quicly_local_cid_set_t *set, size_t size);
/**
 * tells the module that the first `num_sent` pending CIDs have been sent
 */
void quicly_local_cid_on_sent(quicly_local_cid_set_t *set, size_t num_sent);
/**
 * tells the module that the given sequence number was ACKed
 */
void quicly_local_cid_on_acked(quicly_local_cid_set_t *set, uint64_t sequence);
/**
 * tells the module that the given sequence number was lost
 *
 * returns true if there is something to send
 */
int quicly_local_cid_on_lost(quicly_local_cid_set_t *set, uint64_t sequence);
/**
 * remove the specified CID from the storage.
 *
 * Unless the CID has been retired by `retire_prior_to`, the CID generator callback is then called to issue a new CID in its place.
 * `*has_pending` is set to true if there is something to send. `*exhausted` is set to true if a new CID could not be issued in
 * place of the retired one, due to the exhaustion of CIDs; the connection can continue, with fewer CIDs available to the peer.
 * @return 0 if the request was legal, otherwise an error code (a connection error caused by the peer)
 */
quicly_error_t quicly_local_cid_retire(quicly_local_cid_set_t *set, uint64_t sequence, int *has_pending, int *exhausted);
/**
 * Replaces all the CIDs with new ones if the key used by the CID encryptor has changed since they were issued (see
 * `quicly_cid_encryptor_t::get_key_generation`), raising `retire_prior_to` so that the remote peer retires the old ones.
 *
 * The CIDs are replaced only after all of them have been delivered (as the peer retires only the CIDs it has received) and the ones
 * retired by the previous replacement have been retired by the peer (RFC 9000 Section 5.1.2); until then, the caller is expected to
 * call this function again.
 *
 * @return true if the CIDs have been replaced. Otherwise, `*exhausted` is set to true if the CIDs cannot be replaced due to their
 *         exhaustion; the replacement is not attempted again until the key changes again.
 */
int quicly_local_cid_rotate(quicly_local_cid_set_t *set, int *exhausted);

#ifdef __cplusplus
}
#endif

#endif
