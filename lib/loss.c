/*
 * Copyright (c) 2017-2020 Fastly, Kazuho Oku
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

int quicly_loss_detect_loss(quicly_loss_t *r, quicly_loss_do_detect_cb do_detect)
{
    uint32_t delay_until_lost = ((r->rtt.latest > r->rtt.smoothed ? r->rtt.latest : r->rtt.smoothed) * 9 + 7) / 8;
    int64_t loss_time;
    int ret;

    r->loss_time = INT64_MAX;

    if ((ret = do_detect(r, delay_until_lost, &loss_time)) != 0)
        return ret;
    if (loss_time != INT64_MAX)
        r->loss_time = loss_time;

    return 0;
}
