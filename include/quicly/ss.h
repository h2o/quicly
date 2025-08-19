/*
 * Copyright (c) 2024 Viasat Inc.
 * Authors:  Amber Cronin, Jae Won Chung, Mike Foxworthy, Vittorio Parrella, Feng Li, Mark Claypool
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

#ifndef quicly_ss_h
#define quicly_ss_h

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly/cc.h"
#include "quicly/constants.h"
#include <stdint.h>
#include <stdbool.h>

/**
 * Holds pointers to concrete congestion control implementation functions.
 */
typedef struct st_quicly_ss_type_t quicly_ss_type_t;

struct st_quicly_ss_type_t {
    const char* name;
    void (*ss)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
               uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size);
};

extern quicly_ss_type_t quicly_ss_type_rfc2001, quicly_ss_type_search, quicly_ss_type_disabled;

extern quicly_ss_type_t* quicly_ss_all_types[];

#ifdef __cplusplus
}
#endif

#endif
