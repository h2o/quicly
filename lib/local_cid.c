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
#include "quicly/local_cid.h"

static int has_pending(quicly_local_cid_set_t *set)
{
    return set->cids[0].state == QUICLY_LOCAL_CID_STATE_PENDING;
}

static uint8_t *get_next_cid_tag(quicly_local_cid_set_t *set)
{
    return set->_next_cid_tag != NULL ? set->_next_cid_tag : &set->_local_next_cid_tag;
}

/**
 * generates a new CID and assigns the next tag and sequence. returns true if successfully generated.
 */
static int generate_cid(quicly_local_cid_set_t *set, size_t idx)
{
    uint8_t *next_cid_tag = get_next_cid_tag(set);
    if (set->_encryptor == NULL || *next_cid_tag >= QUICLY_MAX_PATH_ID)
        return 0;

    uint8_t tag = (*next_cid_tag)++;
    set->plaintext.path_id = tag;
    set->_encryptor->encrypt_cid(set->_encryptor, &set->cids[idx].cid, set->cids[idx].stateless_reset_token, &set->plaintext);
    set->cids[idx].cid_tag = tag;
    set->cids[idx].sequence = set->_next_sequence++;

    return 1;
}

static void swap_cids(quicly_local_cid_t *a, quicly_local_cid_t *b)
{
    quicly_local_cid_t tmp = *b;
    *b = *a;
    *a = tmp;
}

/**
 * change the state of a CID to PENDING, and move it forward so CIDs in pending state form FIFO
 */
static void do_mark_pending(quicly_local_cid_set_t *set, size_t idx)
{
    set->cids[idx].state = QUICLY_LOCAL_CID_STATE_PENDING;
    for (size_t j = 0; j < idx; j++) {
        if (set->cids[j].state != QUICLY_LOCAL_CID_STATE_PENDING) {
            swap_cids(&set->cids[idx], &set->cids[j]);
            break;
        }
    }
}

static void do_mark_delivered(quicly_local_cid_set_t *set, size_t idx)
{
    if (set->cids[idx].state == QUICLY_LOCAL_CID_STATE_PENDING) {
        /* if transitioning from PENDING, move it backward so the remaining PENDING CIDs come first */
        while (idx + 1 < PTLS_ELEMENTSOF(set->cids) && set->cids[idx + 1].state == QUICLY_LOCAL_CID_STATE_PENDING) {
            swap_cids(&set->cids[idx], &set->cids[idx + 1]);
            idx++;
        }
    }
    set->cids[idx].state = QUICLY_LOCAL_CID_STATE_DELIVERED;
}

void quicly_local_cid_init_set_shared(quicly_local_cid_set_t *set, quicly_cid_encryptor_t *encryptor,
                                      const quicly_cid_plaintext_t *new_cid, uint8_t *next_cid_tag, int allow_empty)
{
    *set = (quicly_local_cid_set_t){
        ._encryptor = encryptor,
        ._size = 1,
        ._next_cid_tag = next_cid_tag,
        ._allow_empty = allow_empty != 0,
    };

    /* if provided, set master id */
    if (new_cid != NULL) {
        assert(new_cid->path_id == 0);
        set->plaintext = *new_cid;
    }

    /* initialize cids[0] */
    if (encryptor != NULL) {
        assert(new_cid != NULL && "master CID must be specified when a non-zero length CID is to be used");
        if (encryptor->get_key_generation != NULL)
            set->key_generation = encryptor->get_key_generation(encryptor);
        if (generate_cid(set, 0)) {
            set->cids[0].state =
                QUICLY_LOCAL_CID_STATE_DELIVERED; /* no need to use NCID frames, the use delivers this CID to the remote peer */
        } else {
            set->cids[0].state = QUICLY_LOCAL_CID_STATE_IDLE;
            set->cids[0].sequence = UINT64_MAX;
            set->cids[0].cid_tag = QUICLY_MAX_PATH_ID;
        }
    } else {
        set->cids[0].state = QUICLY_LOCAL_CID_STATE_DELIVERED;
        set->cids[0].cid_tag = QUICLY_MAX_PATH_ID;
    }

    for (size_t i = 1; i < PTLS_ELEMENTSOF(set->cids); i++) {
        set->cids[i].sequence = UINT64_MAX;
        set->cids[i].cid_tag = QUICLY_MAX_PATH_ID;
    }
}

void quicly_local_cid_init_set(quicly_local_cid_set_t *set, quicly_cid_encryptor_t *encryptor,
                               const quicly_cid_plaintext_t *new_cid)
{
    quicly_local_cid_init_set_shared(set, encryptor, new_cid, NULL, 0);
}

int quicly_local_cid_set_size(quicly_local_cid_set_t *set, size_t size)
{
    assert(set->_size <= size && size <= QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT);
    set->_size = size;

    /* A rotation can leave both generations in the array. Count only the CIDs still available to the peer. */
    size_t available = 0;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++)
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_IDLE && set->cids[i].sequence >= set->retire_prior_to)
            ++available;

    for (size_t i = 0; available < size; i++) {
        assert(i < PTLS_ELEMENTSOF(set->cids));
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_IDLE)
            continue;
        if (!generate_cid(set, i))
            break;
        do_mark_pending(set, i);
        ++available;
    }

    return has_pending(set);
}

void quicly_local_cid_on_sent(quicly_local_cid_set_t *set, size_t num_sent)
{
    assert(num_sent <= PTLS_ELEMENTSOF(set->cids));

    /* first, mark the first `num_sent` CIDs as INFLIGHT */
    for (size_t i = 0; i < num_sent; i++) {
        assert(set->cids[i].state == QUICLY_LOCAL_CID_STATE_PENDING);
        set->cids[i].state = QUICLY_LOCAL_CID_STATE_INFLIGHT;
    }

    /* then move the remaining PENDING CIDs (if any) to the front of the array */
    for (size_t i = num_sent; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_PENDING)
            break;
        swap_cids(&set->cids[i], &set->cids[i - num_sent]);
    }
}

static size_t find_index(const quicly_local_cid_set_t *set, uint64_t sequence)
{
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].sequence == sequence)
            return i;
    }

    return SIZE_MAX;
}

void quicly_local_cid_on_acked(quicly_local_cid_set_t *set, uint64_t sequence)
{
    size_t i = find_index(set, sequence);
    if (i == SIZE_MAX)
        return;

    do_mark_delivered(set, i);
}

int quicly_local_cid_on_lost(quicly_local_cid_set_t *set, uint64_t sequence)
{
    size_t i = find_index(set, sequence);
    if (i == SIZE_MAX)
        return has_pending(set);

    /* if it's already delivered, ignore the packet loss event (no need for retransmission) */
    if (set->cids[i].state == QUICLY_LOCAL_CID_STATE_DELIVERED)
        return has_pending(set);

    do_mark_pending(set, i);

    return 1;
}

quicly_error_t quicly_local_cid_retire(quicly_local_cid_set_t *set, uint64_t sequence, int *_has_pending, int *exhausted)
{
    *exhausted = 0;

    /* find the CID to be retired, also check if there is at least one other CID that is available to the peer (i.e., not retired by
     * `retire_prior_to`) */
    size_t retired_at = SIZE_MAX;
    int becomes_empty = 1;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].state == QUICLY_LOCAL_CID_STATE_IDLE)
            continue;
        if (set->cids[i].sequence == sequence) {
            assert(retired_at == SIZE_MAX);
            retired_at = i;
        } else if (set->cids[i].sequence >= set->retire_prior_to) {
            becomes_empty = 0;
        }
    }

    /* nothing to do if given CID has been retired already */
    if (retired_at == SIZE_MAX) {
        *_has_pending = has_pending(set);
        return 0;
    }

    /* it is a protocol violation for the remote peer to retire the only CID that is available to it */
    if (becomes_empty && !set->_allow_empty)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    /* retire given CID */
    set->cids[retired_at].state = QUICLY_LOCAL_CID_STATE_IDLE;
    set->cids[retired_at].sequence = UINT64_MAX;
    set->cids[retired_at].cid_tag = QUICLY_MAX_PATH_ID;

    /* move following PENDING CIDs to front */
    for (size_t i = retired_at + 1; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_PENDING)
            break;
        swap_cids(&set->cids[i], &set->cids[retired_at]);
        retired_at = i;
    }

    /* generate one new CID, unless the CID being retired has been replaced by `quicly_local_cid_rotate` */
    if (sequence < set->retire_prior_to) {
        *_has_pending = has_pending(set);
    } else if (generate_cid(set, retired_at)) {
        do_mark_pending(set, retired_at);
        *_has_pending = 1;
    } else {
        *_has_pending = has_pending(set);
        *exhausted = 1;
    }

    return 0;
}

int quicly_local_cid_rotate(quicly_local_cid_set_t *set, int *exhausted)
{
    size_t num_cids = 0, i;
    uint64_t new_key_generation;

    *exhausted = 0;

    if (set->_encryptor == NULL || set->_encryptor->get_key_generation == NULL ||
        (new_key_generation = set->_encryptor->get_key_generation(set->_encryptor)) == set->key_generation)
        return 0;

    for (i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].state == QUICLY_LOCAL_CID_STATE_IDLE)
            continue;
        /* "Endpoints SHOULD NOT issue updates of the Retire Prior To field before receiving RETIRE_CONNECTION_ID frames that retire
         * all connection IDs indicated by the previous Retire Prior To value" (RFC 9000 Section 5.1.2) */
        if (set->cids[i].sequence < set->retire_prior_to)
            return 0;
        /* the peer retires only the CIDs that it has received */
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_DELIVERED)
            return 0;
        ++num_cids;
    }

    /* Record the generation read before generating the new CIDs. If the key changes while they are being generated, some of them
     * might be encrypted using the newer key, in which case they are replaced again, rather than the change being missed. */
    set->key_generation = new_key_generation;

    if (num_cids == 0)
        return 0;

    /* All paths use the same tag space. Ensure that every replacement can be issued before retiring any CID. */
    if (*get_next_cid_tag(set) + num_cids > QUICLY_MAX_PATH_ID) {
        *exhausted = 1;
        return 0;
    }

    /* issue new CIDs using the IDLE entries; there are enough, as all the CIDs in use are at or above `retire_prior_to` */
    set->retire_prior_to = set->_next_sequence;
    for (i = 0; num_cids != 0; i++) {
        assert(i < PTLS_ELEMENTSOF(set->cids));
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_IDLE)
            continue;
        int generated = generate_cid(set, i);
        assert(generated);
        do_mark_pending(set, i);
        --num_cids;
    }

    return 1;
}
