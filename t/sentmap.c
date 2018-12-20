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
#include "quicly/sentmap.h"
#include "test.h"

static int on_acked(struct st_quicly_conn_t *conn, int is_ack, quicly_sent_t *sent)
{
    return 0;
}

static size_t num_blocks(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;
    size_t n = 0;

    for (block = map->head; block != NULL; block = block->next)
        ++n;

    return n;
}

void test_sentmap(void)
{
    quicly_sentmap_t map;
    quicly_sent_t *sent;
    uint64_t at;
    size_t i, j;

    quicly_sentmap_init(&map);

    /* save 150 acks, packet number from 1 to 50 */
    for (at = 0; at < 10; ++at)
        for (i = 1; i <= 5; ++i)
            for (j = 0; j < 3; ++j)
                quicly_sentmap_allocate(&map, at * 5 + i, at, on_acked, 0, 1);

    /* check all acks */
    quicly_sentmap_iter_t iter;
    quicly_sentmap_init_iter(&map, &iter);
    for (at = 0; at < 10; ++at) {
        for (i = 1; i <= 5; ++i) {
            for (j = 0; j < 3; ++j) {
                quicly_sent_t *ack = quicly_sentmap_get(&iter);
                ok(ack->packet_number != UINT64_MAX);
                ok(ack->packet_number == at * 5 + i);
                ok(ack->sent_at == at);
                ok(ack->acked == on_acked);
                quicly_sentmap_next(&iter);
            }
        }
    }
    ok(quicly_sentmap_get(&iter)->packet_number == UINT64_MAX);
    ok(num_blocks(&map) == 150 / 16 + 1);

    /* pop acks between 11 <= packet_number <= 40 */
    quicly_sentmap_init_iter(&map, &iter);
    while (quicly_sentmap_get(&iter)->packet_number <= 10) {
        quicly_sentmap_next(&iter);
        ok(quicly_sentmap_get(&iter)->packet_number != UINT64_MAX);
    }
    while ((sent = quicly_sentmap_get(&iter))->packet_number <= 40) {
        quicly_sentmap_on_ack(&map, 0, sent, NULL);
        quicly_sentmap_release(&map, &iter);
        quicly_sentmap_next(&iter);
        ok(quicly_sentmap_get(&iter)->packet_number != UINT64_MAX);
    }

    quicly_sentmap_init_iter(&map, &iter);
    size_t cnt = 0;
    for (; quicly_sentmap_get(&iter)->packet_number != UINT64_MAX; quicly_sentmap_next(&iter)) {
        quicly_sent_t *ack = quicly_sentmap_get(&iter);
        ok(ack->acked != NULL);
        ok(ack->packet_number <= 10 || 40 < ack->packet_number);
        ++cnt;
    }
    ok(cnt == 60);
    ok(num_blocks(&map) == 30 / 16 + 1 + 1 + 30 / 16 + 1);

    quicly_sentmap_dispose(&map);
}
