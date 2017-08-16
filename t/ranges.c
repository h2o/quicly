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
#include "quicly/ranges.h"
#include "test.h"

void test_ranges()
{
    quicly_ranges_t ranges;
    int ret;

#define CHECK(...) \
    do { \
        static const struct st_quicly_range_t expected[] = {__VA_ARGS__}; \
        ok(ranges.num_ranges == sizeof(expected) / sizeof(expected[0])); \
        size_t i; \
        for (i = 0; i != ranges.num_ranges; ++i) { \
            ok(ranges.ranges[i].start == expected[i].start); \
            ok(ranges.ranges[i].end == expected[i].end); \
        } \
    } while (0)

    quicly_ranges_init(&ranges);
    ok(ranges.num_ranges == 0);

    ret = quicly_ranges_update(&ranges, 40, 100);
    ok(ret == 0);
    CHECK({40, 100});

    ret = quicly_ranges_update(&ranges, 30, 40);
    ok(ret == 0);
    CHECK({30, 100});

    ret = quicly_ranges_update(&ranges, 0, 10);
    ok(ret == 0);
    CHECK({0, 10}, {30, 100});

    ret = quicly_ranges_update(&ranges, 10, 30);
    ok(ret == 0);
    CHECK({0, 100});

    ret = quicly_ranges_update(&ranges, 200, 300);
    ok(ret == 0);
    CHECK({0, 100}, {200, 300});

    ret = quicly_ranges_update(&ranges, 100, 110);
    ok(ret == 0);
    CHECK({0, 110}, {200, 300});

    ret = quicly_ranges_update(&ranges, 190, 200);
    ok(ret == 0);
    CHECK({0, 110}, {190, 300});

    ret = quicly_ranges_update(&ranges, 100, 120);
    ok(ret == 0);
    CHECK({0, 120}, {190, 300});

    ret = quicly_ranges_update(&ranges, 180, 200);
    ok(ret == 0);
    CHECK({0, 120}, {180, 300});

    ret = quicly_ranges_update(&ranges, 130, 150);
    ok(ret == 0);
    CHECK({0, 120}, {130, 150}, {180, 300});

    ret = quicly_ranges_update(&ranges, 160, 170);
    ok(ret == 0);
    CHECK({0, 120}, {130, 150}, {160, 170}, {180, 300});

    ret = quicly_ranges_update(&ranges, 170, 180);
    ok(ret == 0);
    CHECK({0, 120}, {130, 150}, {160, 300});

    ret = quicly_ranges_update(&ranges, 110, 180);
    ok(ret == 0);
    CHECK({0, 300});
}
