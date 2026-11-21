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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "../lib/quicly.c"
#include "test.h"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEpAIBAAKCAQEA7zZheZ4ph98JaedBNv9kqsVA9CSmhd69kBc9ZAfVFMA4VQwp\n"                                                           \
    "rOj3ZGrxf20HB3FkvqGvew9ZogUF6NjbPumeiUObGpP21Y5wcYlPL4aojlrwMB/e\n"                                                           \
    "OxOCpuRyQTRSSe1hDPvdJABQdmshDP5ZSEBLdUSgrNn4KWhIDjFj1AHXIMqeqTXe\n"                                                           \
    "tFuRgNzHdtbXQx+UWBis2B6qZJuqSArb2msVOC8D5gNznPPlQw7FbdPCaLNXSb6G\n"                                                           \
    "nI0E0uj6QmYlAw9s6nkgP/zxjfFldqPNUprGcEqTwmAb8VVtd7XbANYrzubZ4Nn6\n"                                                           \
    "/WXrCrVxWUmh/7Spgdwa/I4Nr1JHv9HHyL2z/wIDAQABAoIBAEVPf2zKrAPnVwXt\n"                                                           \
    "cJLr6xIj908GM43EXS6b3TjXoCDUFT5nOMgV9GCPMAwY3hmE/IjTtlG0v+bXB8BQ\n"                                                           \
    "3S3caQgio5VO3A1CqUfsXhpKLRqaNM/s2+pIG+oZdRV5gIJVGnK1o3yj7qxxG/F0\n"                                                           \
    "3Q+3OWXwDZIn0eTFh2M9YkxygA/KtkREZWv8Q8qZpdOpJSBYZyGE97Jqy/yGc+DQ\n"                                                           \
    "Vpoa9B8WwnIdUn47TkZfsbzqGIYZxatJQDC1j7Y+F8So7zBbUhpz7YqATQwf5Efm\n"                                                           \
    "K2xwvlwfdwykq6ffEr2M/Xna0220G2JZlGq3Cs2X9GT9Pt9OS86Bz+EL46ELo0tZ\n"                                                           \
    "yfHQe/kCgYEA+zh4k2be6fhQG+ChiG3Ue5K/kH2prqyGBus61wHnt8XZavqBevEy\n"                                                           \
    "4pdmvJ6Q1Ta9Z2YCIqqNmlTdjZ6B35lvAK8YFITGy0MVV6K5NFYVfhALWCQC2r3B\n"                                                           \
    "6uH39FQ0mDo3gS5ZjYlUzbu67LGFnyX+pyMr2oxlhI1fCY3VchXQAOsCgYEA88Nt\n"                                                           \
    "CwSOaZ1fWmyNAgXEAX1Jx4XLFYgjcA/YBXW9gfQ0AfufB346y53PsgjX1lB+Bbcg\n"                                                           \
    "cY/o5W7F0b3A0R4K5LShlPCq8iB2DC+VnpKwTgo8ylh+VZCPy2BmMK0jrrmyqWeg\n"                                                           \
    "PzwgP0lp+7l/qW8LDImeYi8nWoqd6f1ye4iJdD0CgYEAlIApJljk5EFYeWIrmk3y\n"                                                           \
    "EKoKewsNRqfNAkICoh4KL2PQxaAW8emqPq9ol47T5nVZOMnf8UYINnZ8EL7l3psA\n"                                                           \
    "NtNJ1Lc4G+cnsooKGJnaUo6BZjTDSzJocsPoopE0Fdgz/zS60yOe8Y5LTKcTaaQ4\n"                                                           \
    "B+yOe74KNHSs/STOS4YBUskCgYAIqaRBZPsOo8oUs5DbRostpl8t2QJblIf13opF\n"                                                           \
    "v2ZprN0ASQngwUqjm8sav5e0BQ5Fc7mSb5POO36KMp0ckV2/vO+VFGxuyFqJmlNN\n"                                                           \
    "3Fapn1GDu1tZ/RYvGxDmn/CJsA26WXVnaeKXfStoB7KSueCBpI5dXOGgJRbxjtE3\n"                                                           \
    "tKV13QKBgQCtmLtTJPJ0Z+9n85C8kBonk2MCnD9JTYWoDQzNMYGabthzSqJqcEek\n"                                                           \
    "dvhr82XkcHM+r6+cirjdQr4Qj7/2bfZesHl5XLvoJDB1YJIXnNJOELwbktrJrXLc\n"                                                           \
    "dJ+MMvPvBAMah/tqr2DqgTGfWLDt9PJiCJVsuN2kD9toWHV08pY0Og==\n"                                                                   \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIIDOjCCAiKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDEwtIMk8g\n"                                                           \
    "VGVzdCBDQTAeFw0xNDEyMTAxOTMzMDVaFw0yNDEyMDcxOTMzMDVaMBsxGTAXBgNV\n"                                                           \
    "BAMTEDEyNy4wLjAuMS54aXAuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"                                                           \
    "AoIBAQDvNmF5nimH3wlp50E2/2SqxUD0JKaF3r2QFz1kB9UUwDhVDCms6PdkavF/\n"                                                           \
    "bQcHcWS+oa97D1miBQXo2Ns+6Z6JQ5sak/bVjnBxiU8vhqiOWvAwH947E4Km5HJB\n"                                                           \
    "NFJJ7WEM+90kAFB2ayEM/llIQEt1RKCs2fgpaEgOMWPUAdcgyp6pNd60W5GA3Md2\n"                                                           \
    "1tdDH5RYGKzYHqpkm6pICtvaaxU4LwPmA3Oc8+VDDsVt08Jos1dJvoacjQTS6PpC\n"                                                           \
    "ZiUDD2zqeSA//PGN8WV2o81SmsZwSpPCYBvxVW13tdsA1ivO5tng2fr9ZesKtXFZ\n"                                                           \
    "SaH/tKmB3Br8jg2vUke/0cfIvbP/AgMBAAGjgY0wgYowCQYDVR0TBAIwADAsBglg\n"                                                           \
    "hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\n"                                                           \
    "BBYEFJXhddVQ68vtPvxoHWHsYkLnu3+4MDAGA1UdIwQpMCehGqQYMBYxFDASBgNV\n"                                                           \
    "BAMTC0gyTyBUZXN0IENBggkAmqS1V7DvzbYwDQYJKoZIhvcNAQELBQADggEBAJQ2\n"                                                           \
    "uvzL/lZnrsF4cvHhl/mg+s/RjHwvqFRrxOWUeWu2BQOGdd1Izqr8ZbF35pevPkXe\n"                                                           \
    "j3zQL4Nf8OxO/gx4w0165KL4dYxEW7EaxsDQUI2aXSW0JNSvK2UGugG4+E4aT+9y\n"                                                           \
    "cuBCtfWbL4/N6IMt2QW17B3DcigkreMoZavnnqRecQWkOx4nu0SmYg1g2QV4kRqT\n"                                                           \
    "nvLt29daSWjNhP3dkmLTxn19umx26/JH6rqcgokDfHHO8tlDbc9JfyxYH01ZP2Ps\n"                                                           \
    "esIiGa/LBXfKiPXxyHuNVQI+2cMmIWYf+Eu/1uNV3K55fA8806/FeklcQe/vvSCU\n"                                                           \
    "Vw6RN5S/14SQnMYWr7E=\n"                                                                                                       \
    "-----END CERTIFICATE-----\n"

static void on_destroy(quicly_stream_t *stream, quicly_error_t err);
static void on_egress_stop(quicly_stream_t *stream, quicly_error_t err);
static void on_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void on_ingress_reset(quicly_stream_t *stream, quicly_error_t err);

quicly_address_t fake_address;
int64_t quic_now = 1;
static double quic_now_submillisec;
quicly_context_t quic_ctx;
quicly_stream_callbacks_t stream_callbacks = {
    on_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_egress_stop, on_ingress_receive, on_ingress_reset};
size_t on_destroy_callcnt;

static ptls_cipher_context_t *test_random_cipher;

/* keep protocol-level random choices reproducible; cryptographic primitives are tested separately */
static void test_random_bytes(void *buf, size_t len)
{
    static const uint8_t zeroes[64] = {0};

    assert(test_random_cipher != NULL);
    while (len != 0) {
        size_t chunk = len < sizeof(zeroes) ? len : sizeof(zeroes);
        ptls_cipher_encrypt(test_random_cipher, buf, zeroes, chunk);
        buf = (uint8_t *)buf + chunk;
        len -= chunk;
    }
}

static void test_error_codes(void)
{
    quicly_error_t a;

    a = QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0);

    a = QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x3fffffffffffffff);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0x3fffffffffffffff);

    a = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0);

    a = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x3fffffffffffffff);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0x3fffffffffffffff);

    a = 0;
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = PTLS_ALERT_UNKNOWN_CA; /* arbitrary alert */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = 0x2ffff; /* max outside QUIC errors */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = (int64_t)0x8000000000030000; /* min outside QUIC errors */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = QUICLY_ERROR_PACKET_IGNORED; /* arbrary internal error */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));
}

static void test_select_with_ratio255(void)
{
    { /* single slot */
        uint8_t ratios[] = {0};
        ok(do_select_with_ratio255(ratios, 1, 0) == 0);
        ok(do_select_with_ratio255(ratios, 1, 254) == 0);
        ratios[0] = 63;
        ok(do_select_with_ratio255(ratios, 1, 0) == 1);
        ok(do_select_with_ratio255(ratios, 1, 62) == 1);
        ok(do_select_with_ratio255(ratios, 1, 63) == 0);
        ratios[0] = 255;
        ok(do_select_with_ratio255(ratios, 1, 0) == 1);
        ok(do_select_with_ratio255(ratios, 1, 254) == 1);
    }

    { /* multiple slots, with a gap */
        uint8_t ratios[] = {64, 0, 32};
        ok(do_select_with_ratio255(ratios, 3, 0) == 1);
        ok(do_select_with_ratio255(ratios, 3, 63) == 1);
        ok(do_select_with_ratio255(ratios, 3, 64) == 3);
        ok(do_select_with_ratio255(ratios, 3, 95) == 3);
        ok(do_select_with_ratio255(ratios, 3, 96) == 0);
        ok(do_select_with_ratio255(ratios, 3, 254) == 0);
    }

    { /* multiple slots adding up to 255 */
        uint8_t ratios[] = {85, 85, 85};
        ok(do_select_with_ratio255(ratios, 3, 84) == 1);
        ok(do_select_with_ratio255(ratios, 3, 85) == 2);
        ok(do_select_with_ratio255(ratios, 3, 170) == 3);
        ok(do_select_with_ratio255(ratios, 3, 254) == 3);
    }
}

static void test_egress_selection(void)
{
    quicly_context_t ctx = quic_ctx;

    for (size_t alt = 0; alt <= QUICLY_NUM_ALT_EGRESS; ++alt) {
        memset(ctx.alt_egress_ratio, 0, sizeof(ctx.alt_egress_ratio));
        if (alt != 0) {
            ctx.egress[alt] = ctx.egress[0];
            ctx.egress[alt].pacing = 1; /* mark the slot to check that it is the one being used */
            ctx.alt_egress_ratio[alt - 1] = 255;
        }
        quicly_conn_t *conn;
        ok(quicly_connect(&conn, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                          NULL) == 0);
        ok(quicly_get_alt_egress(conn) == alt);
        ok(get_egress_context(conn) == &ctx.egress[alt]);
        ok((conn->path_spaces[0]->pacer != NULL) == (alt != 0 || ctx.egress[0].pacing));
        quicly_stats_t stats;
        ok(quicly_get_stats(conn, &stats) == 0);
        ok(stats.num_alt_egress == (alt != 0));
        quicly_free(conn);
    }
}

static void test_adjust_stream_frame_layout(void)
{
#define TEST(_is_crypto, _capacity, check)                                                                                         \
    do {                                                                                                                           \
        uint8_t buf[] = {0xff, 0x04, 'h', 'e', 'l', 'l', 'o', 0, 0, 0};                                                            \
        uint8_t *dst = buf + 2, *const dst_end = buf + _capacity, *frame_at = buf;                                                 \
        size_t len = 5;                                                                                                            \
        int wrote_all = 1;                                                                                                         \
        buf[0] = _is_crypto ? 0x06 : 0x08;                                                                                         \
        adjust_stream_frame_layout(&dst, dst_end, &len, &wrote_all, &frame_at);                                                    \
        do {                                                                                                                       \
            check                                                                                                                  \
        } while (0);                                                                                                               \
    } while (0);

    /* test CRYPTO frames that fit and don't when length is inserted */
    TEST(1, 10, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x06\x04\x05hello", 8) == 0);
    });
    TEST(1, 8, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x06\x04\x05hello", 8) == 0);
    });
    TEST(1, 7, {
        ok(dst == buf + 7);
        ok(len == 4);
        ok(!wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x06\x04\x04hell", 7) == 0);
    });

    /* test STREAM frames */
    TEST(0, 9, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x0a\x04\x05hello", 8) == 0);
    });
    TEST(0, 8, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf + 1);
        ok(memcmp(buf, "\x00\x08\x04hello", 8) == 0);
    });
    TEST(0, 7, {
        ok(dst == buf + 7);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x08\x04hello", 7) == 0);
    });

#undef TEST
}

/**
 * When a CRYPTO frame is shortened to make room for the length field, the length field must be sized for the shortened length,
 * and the payload must be the largest that fits in the space.
 */
static void test_adjust_crypto_frame_layout(void)
{
    /* minimum, both sides of the boundary of 1-byte and 2-byte length fields, and a large frame */
    static const size_t capacities[] = {2, 64, 65, 1200};
    static const size_t expected_lens[] = {1, 63, 63, 1198};
    static uint8_t buf[2 + 1200], expected[1200];

    for (size_t i = 0; i < sizeof(expected); ++i)
        expected[i] = (uint8_t)(i * 7 + 1);

    for (size_t i = 0; i < PTLS_ELEMENTSOF(capacities); ++i) {
        size_t capacity = capacities[i];
        /* CRYPTO frame at offset zero, with payload filling all the space being available */
        buf[0] = QUICLY_FRAME_TYPE_CRYPTO;
        buf[1] = 0;
        memcpy(buf + 2, expected, capacity);
        uint8_t *dst = buf + 2, *const dst_end = buf + 2 + capacity, *frame_at = buf;
        size_t len = capacity;
        int wrote_all = 1;
        adjust_stream_frame_layout(&dst, dst_end, &len, &wrote_all, &frame_at);

        ok(dst <= dst_end);
        ok(!wrote_all);
        ok(frame_at == buf);
        ok(len == expected_lens[i]);
        const uint8_t *src = buf + 1; /* skip the frame type */
        quicly_stream_frame_t frame;
        ok(quicly_decode_crypto_frame(&src, dst, &frame) == 0);
        ok(src == dst);
        ok(frame.offset == 0);
        ok(frame.data.len == len);
        ok(memcmp(frame.data.base, expected, len) == 0);
    }
}

static void get_now_cb(quicly_now_t *self, double *now)
{
    *now = quic_now + quic_now_submillisec;
}

static quicly_now_t get_now = {get_now_cb};

void on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
    test_streambuf_t *sbuf = stream->data;
    sbuf->is_detached = 1;
    ++on_destroy_callcnt;
}

void on_egress_stop(quicly_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    test_streambuf_t *sbuf = stream->data;
    sbuf->error_received.stop_sending = err;
}

void on_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    test_streambuf_t *sbuf = stream->data;

    quicly_streambuf_ingress_receive(stream, off, src, len);

    /* the end of the stream is notified once, and a reset being notified here is never notified through `on_receive_reset` */
    if (quicly_recvstate_transfer_complete(&stream->recvstate) && stream->recvstate.app_error_code != UINT64_MAX) {
        assert(sbuf->error_received.reset_on_receive == -1 && sbuf->error_received.reset_stream == -1);
        sbuf->error_received.reset_on_receive = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(stream->recvstate.app_error_code);
    }
}

void on_ingress_reset(quicly_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    test_streambuf_t *sbuf = stream->data;
    assert(sbuf->error_received.reset_on_receive == -1 && sbuf->error_received.reset_stream == -1);
    sbuf->error_received.reset_stream = err;
}

const quicly_cid_plaintext_t *new_master_id(void)
{
    static quicly_cid_plaintext_t master = {UINT32_MAX};
    ++master.master_id;
    return &master;
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    test_streambuf_t *sbuf;
    int ret;

    ret = quicly_streambuf_create(stream, sizeof(*sbuf));
    assert(ret == 0);
    sbuf = stream->data;
    sbuf->error_received.stop_sending = -1;
    sbuf->error_received.reset_stream = -1;
    sbuf->error_received.reset_on_receive = -1;
    stream->callbacks = &stream_callbacks;

    return 0;
}

quicly_stream_open_t stream_open = {on_stream_open};

static void test_vector(void)
{
    static const uint8_t expected_payload[] = {
        0x06, 0x00, 0x40, 0xc4, 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0x66, 0x60, 0x26, 0x1f, 0xf9, 0x47, 0xce, 0xa4, 0x9c, 0xce,
        0x6c, 0xfa, 0xd6, 0x87, 0xf4, 0x57, 0xcf, 0x1b, 0x14, 0x53, 0x1b, 0xa1, 0x41, 0x31, 0xa0, 0xe8, 0xf3, 0x09, 0xa1, 0xd0,
        0xb9, 0xc4, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00,
        0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00,
        0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x4c, 0xfd, 0xfc, 0xd1, 0x78, 0xb7, 0x84,
        0xbf, 0x32, 0x8c, 0xae, 0x79, 0x3b, 0x13, 0x6f, 0x2a, 0xed, 0xce, 0x00, 0x5f, 0xf1, 0x83, 0xd7, 0xbb, 0x14, 0x95, 0x20,
        0x72, 0x36, 0x64, 0x70, 0x37, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
        0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01};
    uint8_t datagram[] = {
        0xc5, 0xff, 0x00, 0x00, 0x1d, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x4a, 0x95,
        0x24, 0x5b, 0xfb, 0x66, 0xbc, 0x5f, 0x93, 0x03, 0x2b, 0x7d, 0xdd, 0x89, 0xfe, 0x0f, 0xf1, 0x5d, 0x9c, 0x4f, 0x70, 0x50,
        0xfc, 0xcd, 0xb7, 0x1c, 0x1c, 0xd8, 0x05, 0x12, 0xd4, 0x43, 0x16, 0x43, 0xa5, 0x3a, 0xaf, 0xa1, 0xb0, 0xb5, 0x18, 0xb4,
        0x49, 0x68, 0xb1, 0x8b, 0x8d, 0x3e, 0x7a, 0x4d, 0x04, 0xc3, 0x0b, 0x3e, 0xd9, 0x41, 0x03, 0x25, 0xb2, 0xab, 0xb2, 0xda,
        0xfb, 0x1c, 0x12, 0xf8, 0xb7, 0x04, 0x79, 0xeb, 0x8d, 0xf9, 0x8a, 0xbc, 0xaf, 0x95, 0xdd, 0x8f, 0x3d, 0x1c, 0x78, 0x66,
        0x0f, 0xbc, 0x71, 0x9f, 0x88, 0xb2, 0x3c, 0x8a, 0xef, 0x67, 0x71, 0xf3, 0xd5, 0x0e, 0x10, 0xfd, 0xfb, 0x4c, 0x9d, 0x92,
        0x38, 0x6d, 0x44, 0x48, 0x1b, 0x6c, 0x52, 0xd5, 0x9e, 0x55, 0x38, 0xd3, 0xd3, 0x94, 0x2d, 0xe9, 0xf1, 0x3a, 0x7f, 0x8b,
        0x70, 0x2d, 0xc3, 0x17, 0x24, 0x18, 0x0d, 0xa9, 0xdf, 0x22, 0x71, 0x4d, 0x01, 0x00, 0x3f, 0xc5, 0xe3, 0xd1, 0x65, 0xc9,
        0x50, 0xe6, 0x30, 0xb8, 0x54, 0x0f, 0xbd, 0x81, 0xc9, 0xdf, 0x0e, 0xe6, 0x3f, 0x94, 0x99, 0x70, 0x26, 0xc4, 0xf2, 0xe1,
        0x88, 0x7a, 0x2d, 0xef, 0x79, 0x05, 0x0a, 0xc2, 0xd8, 0x6b, 0xa3, 0x18, 0xe0, 0xb3, 0xad, 0xc4, 0xc5, 0xaa, 0x18, 0xbc,
        0xf6, 0x3c, 0x7c, 0xf8, 0xe8, 0x5f, 0x56, 0x92, 0x49, 0x81, 0x3a, 0x22, 0x36, 0xa7, 0xe7, 0x22, 0x69, 0x44, 0x7c, 0xd1,
        0xc7, 0x55, 0xe4, 0x51, 0xf5, 0xe7, 0x74, 0x70, 0xeb, 0x3d, 0xe6, 0x4c, 0x88, 0x49, 0xd2, 0x92, 0x82, 0x06, 0x98, 0x02,
        0x9c, 0xfa, 0x18, 0xe5, 0xd6, 0x61, 0x76, 0xfe, 0x6e, 0x5b, 0xa4, 0xed, 0x18, 0x02, 0x6f, 0x90, 0x90, 0x0a, 0x5b, 0x49,
        0x80, 0xe2, 0xf5, 0x8e, 0x39, 0x15, 0x1d, 0x5c, 0xd6, 0x85, 0xb1, 0x09, 0x29, 0x63, 0x6d, 0x4f, 0x02, 0xe7, 0xfa, 0xd2,
        0xa5, 0xa4, 0x58, 0x24, 0x9f, 0x5c, 0x02, 0x98, 0xa6, 0xd5, 0x3a, 0xcb, 0xe4, 0x1a, 0x7f, 0xc8, 0x3f, 0xa7, 0xcc, 0x01,
        0x97, 0x3f, 0x7a, 0x74, 0xd1, 0x23, 0x7a, 0x51, 0x97, 0x4e, 0x09, 0x76, 0x36, 0xb6, 0x20, 0x39, 0x97, 0xf9, 0x21, 0xd0,
        0x7b, 0xc1, 0x94, 0x0a, 0x6f, 0x2d, 0x0d, 0xe9, 0xf5, 0xa1, 0x14, 0x32, 0x94, 0x61, 0x59, 0xed, 0x6c, 0xc2, 0x1d, 0xf6,
        0x5c, 0x4d, 0xdd, 0x11, 0x15, 0xf8, 0x64, 0x27, 0x25, 0x9a, 0x19, 0x6c, 0x71, 0x48, 0xb2, 0x5b, 0x64, 0x78, 0xb0, 0xdc,
        0x77, 0x66, 0xe1, 0xc4, 0xd1, 0xb1, 0xf5, 0x15, 0x9f, 0x90, 0xea, 0xbc, 0x61, 0x63, 0x62, 0x26, 0x24, 0x46, 0x42, 0xee,
        0x14, 0x8b, 0x46, 0x4c, 0x9e, 0x61, 0x9e, 0xe5, 0x0a, 0x5e, 0x3d, 0xdc, 0x83, 0x62, 0x27, 0xca, 0xd9, 0x38, 0x98, 0x7c,
        0x4e, 0xa3, 0xc1, 0xfa, 0x7c, 0x75, 0xbb, 0xf8, 0x8d, 0x89, 0xe9, 0xad, 0xa6, 0x42, 0xb2, 0xb8, 0x8f, 0xe8, 0x10, 0x7b,
        0x7e, 0xa3, 0x75, 0xb1, 0xb6, 0x48, 0x89, 0xa4, 0xe9, 0xe5, 0xc3, 0x8a, 0x1c, 0x89, 0x6c, 0xe2, 0x75, 0xa5, 0x65, 0x8d,
        0x25, 0x0e, 0x2d, 0x76, 0xe1, 0xed, 0x3a, 0x34, 0xce, 0x7e, 0x3a, 0x3f, 0x38, 0x3d, 0x0c, 0x99, 0x6d, 0x0b, 0xed, 0x10,
        0x6c, 0x28, 0x99, 0xca, 0x6f, 0xc2, 0x63, 0xef, 0x04, 0x55, 0xe7, 0x4b, 0xb6, 0xac, 0x16, 0x40, 0xea, 0x7b, 0xfe, 0xdc,
        0x59, 0xf0, 0x3f, 0xee, 0x0e, 0x17, 0x25, 0xea, 0x15, 0x0f, 0xf4, 0xd6, 0x9a, 0x76, 0x60, 0xc5, 0x54, 0x21, 0x19, 0xc7,
        0x1d, 0xe2, 0x70, 0xae, 0x7c, 0x3e, 0xcf, 0xd1, 0xaf, 0x2c, 0x4c, 0xe5, 0x51, 0x98, 0x69, 0x49, 0xcc, 0x34, 0xa6, 0x6b,
        0x3e, 0x21, 0x6b, 0xfe, 0x18, 0xb3, 0x47, 0xe6, 0xc0, 0x5f, 0xd0, 0x50, 0xf8, 0x59, 0x12, 0xdb, 0x30, 0x3a, 0x8f, 0x05,
        0x4e, 0xc2, 0x3e, 0x38, 0xf4, 0x4d, 0x1c, 0x72, 0x5a, 0xb6, 0x41, 0xae, 0x92, 0x9f, 0xec, 0xc8, 0xe3, 0xce, 0xfa, 0x56,
        0x19, 0xdf, 0x42, 0x31, 0xf5, 0xb4, 0xc0, 0x09, 0xfa, 0x0c, 0x0b, 0xbc, 0x60, 0xbc, 0x75, 0xf7, 0x6d, 0x06, 0xef, 0x15,
        0x4f, 0xc8, 0x57, 0x70, 0x77, 0xd9, 0xd6, 0xa1, 0xd2, 0xbd, 0x9b, 0xf0, 0x81, 0xdc, 0x78, 0x3e, 0xce, 0x60, 0x11, 0x1b,
        0xea, 0x7d, 0xa9, 0xe5, 0xa9, 0x74, 0x80, 0x69, 0xd0, 0x78, 0xb2, 0xbe, 0xf4, 0x8d, 0xe0, 0x4c, 0xab, 0xe3, 0x75, 0x5b,
        0x19, 0x7d, 0x52, 0xb3, 0x20, 0x46, 0x94, 0x9e, 0xca, 0xa3, 0x10, 0x27, 0x4b, 0x4a, 0xac, 0x0d, 0x00, 0x8b, 0x19, 0x48,
        0xc1, 0x08, 0x2c, 0xdf, 0xe2, 0x08, 0x3e, 0x38, 0x6d, 0x4f, 0xd8, 0x4c, 0x0e, 0xd0, 0x66, 0x6d, 0x3e, 0xe2, 0x6c, 0x45,
        0x15, 0xc4, 0xfe, 0xe7, 0x34, 0x33, 0xac, 0x70, 0x3b, 0x69, 0x0a, 0x9f, 0x7b, 0xf2, 0x78, 0xa7, 0x74, 0x86, 0xac, 0xe4,
        0x4c, 0x48, 0x9a, 0x0c, 0x7a, 0xc8, 0xdf, 0xe4, 0xd1, 0xa5, 0x8f, 0xb3, 0xa7, 0x30, 0xb9, 0x93, 0xff, 0x0f, 0x0d, 0x61,
        0xb4, 0xd8, 0x95, 0x57, 0x83, 0x1e, 0xb4, 0xc7, 0x52, 0xff, 0xd3, 0x9c, 0x10, 0xf6, 0xb9, 0xf4, 0x6d, 0x8d, 0xb2, 0x78,
        0xda, 0x62, 0x4f, 0xd8, 0x00, 0xe4, 0xaf, 0x85, 0x54, 0x8a, 0x29, 0x4c, 0x15, 0x18, 0x89, 0x3a, 0x87, 0x78, 0xc4, 0xf6,
        0xd6, 0xd7, 0x3c, 0x93, 0xdf, 0x20, 0x09, 0x60, 0x10, 0x4e, 0x06, 0x2b, 0x38, 0x8e, 0xa9, 0x7d, 0xcf, 0x40, 0x16, 0xbc,
        0xed, 0x7f, 0x62, 0xb4, 0xf0, 0x62, 0xcb, 0x6c, 0x04, 0xc2, 0x06, 0x93, 0xd9, 0xa0, 0xe3, 0xb7, 0x4b, 0xa8, 0xfe, 0x74,
        0xcc, 0x01, 0x23, 0x78, 0x84, 0xf4, 0x0d, 0x76, 0x5a, 0xe5, 0x6a, 0x51, 0x68, 0x8d, 0x98, 0x5c, 0xf0, 0xce, 0xae, 0xf4,
        0x30, 0x45, 0xed, 0x8c, 0x3f, 0x0c, 0x33, 0xbc, 0xed, 0x08, 0x53, 0x7f, 0x68, 0x82, 0x61, 0x3a, 0xcd, 0x3b, 0x08, 0xd6,
        0x65, 0xfc, 0xe9, 0xdd, 0x8a, 0xa7, 0x31, 0x71, 0xe2, 0xd3, 0x77, 0x1a, 0x61, 0xdb, 0xa2, 0x79, 0x0e, 0x49, 0x1d, 0x41,
        0x3d, 0x93, 0xd9, 0x87, 0xe2, 0x74, 0x5a, 0xf2, 0x94, 0x18, 0xe4, 0x28, 0xbe, 0x34, 0x94, 0x14, 0x85, 0xc9, 0x34, 0x47,
        0x52, 0x0f, 0xfe, 0x23, 0x1d, 0xa2, 0x30, 0x4d, 0x6a, 0x0f, 0xd5, 0xd0, 0x7d, 0x08, 0x37, 0x22, 0x02, 0x36, 0x96, 0x61,
        0x59, 0xbe, 0xf3, 0xcf, 0x90, 0x4d, 0x72, 0x23, 0x24, 0xdd, 0x85, 0x25, 0x13, 0xdf, 0x39, 0xae, 0x03, 0x0d, 0x81, 0x73,
        0x90, 0x8d, 0xa6, 0x36, 0x47, 0x86, 0xd3, 0xc1, 0xbf, 0xcb, 0x19, 0xea, 0x77, 0xa6, 0x3b, 0x25, 0xf1, 0xe7, 0xfc, 0x66,
        0x1d, 0xef, 0x48, 0x0c, 0x5d, 0x00, 0xd4, 0x44, 0x56, 0x26, 0x9e, 0xbd, 0x84, 0xef, 0xd8, 0xe3, 0xa8, 0xb2, 0xc2, 0x57,
        0xee, 0xc7, 0x60, 0x60, 0x68, 0x28, 0x48, 0xcb, 0xf5, 0x19, 0x4b, 0xc9, 0x9e, 0x49, 0xee, 0x75, 0xe4, 0xd0, 0xd2, 0x54,
        0xba, 0xd4, 0xbf, 0xd7, 0x49, 0x70, 0xc3, 0x0e, 0x44, 0xb6, 0x55, 0x11, 0xd4, 0xad, 0x0e, 0x6e, 0xc7, 0x39, 0x8e, 0x08,
        0xe0, 0x13, 0x07, 0xee, 0xee, 0xa1, 0x4e, 0x46, 0xcc, 0xd8, 0x7c, 0xf3, 0x6b, 0x28, 0x52, 0x21, 0x25, 0x4d, 0x8f, 0xc6,
        0xa6, 0x76, 0x5c, 0x52, 0x4d, 0xed, 0x00, 0x85, 0xdc, 0xa5, 0xbd, 0x68, 0x8d, 0xdf, 0x72, 0x2e, 0x2c, 0x0f, 0xaf, 0x9d,
        0x0f, 0xb2, 0xce, 0x7a, 0x0c, 0x3f, 0x2c, 0xee, 0x19, 0xca, 0x0f, 0xfb, 0xa4, 0x61, 0xca, 0x8d, 0xc5, 0xd2, 0xc8, 0x17,
        0x8b, 0x07, 0x62, 0xcf, 0x67, 0x13, 0x55, 0x58, 0x49, 0x4d, 0x2a, 0x96, 0xf1, 0xa1, 0x39, 0xf0, 0xed, 0xb4, 0x2d, 0x2a,
        0xf8, 0x9a, 0x9c, 0x91, 0x22, 0xb0, 0x7a, 0xcb, 0xc2, 0x9e, 0x5e, 0x72, 0x2d, 0xf8, 0x61, 0x5c, 0x34, 0x37, 0x02, 0x49,
        0x10, 0x98, 0x47, 0x8a, 0x38, 0x9c, 0x98, 0x72, 0xa1, 0x0b, 0x0c, 0x98, 0x75, 0x12, 0x5e, 0x25, 0x7c, 0x7b, 0xfd, 0xf2,
        0x7e, 0xef, 0x40, 0x60, 0xbd, 0x3d, 0x00, 0xf4, 0xc1, 0x4f, 0xd3, 0xe3, 0x49, 0x6c, 0x38, 0xd3, 0xc5, 0xd1, 0xa5, 0x66,
        0x8c, 0x39, 0x35, 0x0e, 0xff, 0xbc, 0x2d, 0x16, 0xca, 0x17, 0xbe, 0x4c, 0xe2, 0x9f, 0x02, 0xed, 0x96, 0x95, 0x04, 0xdd,
        0xa2, 0xa8, 0xc6, 0xb9, 0xff, 0x91, 0x9e, 0x69, 0x3e, 0xe7, 0x9e, 0x09, 0x08, 0x93, 0x16, 0xe7, 0xd1, 0xd8, 0x9e, 0xc0,
        0x99, 0xdb, 0x3b, 0x2b, 0x26, 0x87, 0x25, 0xd8, 0x88, 0x53, 0x6a, 0x4b, 0x8b, 0xf9, 0xae, 0xe8, 0xfb, 0x43, 0xe8, 0x2a,
        0x4d, 0x91, 0x9d, 0x48, 0x43, 0xb1, 0xca, 0x70, 0xa2, 0xd8, 0xd3, 0xf7, 0x25, 0xea, 0xd1, 0x39, 0x13, 0x77, 0xdc, 0xc0};
    quicly_decoded_packet_t packet;
    struct st_quicly_cipher_context_t ingress, egress;
    uint64_t pn;
    ptls_iovec_t payload;
    int ret;

    /* decode */
    size_t off = 0;
    ok(quicly_decode_packet(&quic_ctx, &packet, datagram, sizeof(datagram), &off) == sizeof(datagram));
    ok(off == sizeof(datagram));

    /* decrypt */
    const quicly_salt_t *salt = quicly_get_salt(QUICLY_PROTOCOL_VERSION_DRAFT29);
    ret = setup_initial_encryption(&ptls_openssl_aes128gcmsha256, &ingress, &egress, packet.cid.dest.encrypted, 0,
                                   ptls_iovec_init(salt->initial, sizeof(salt->initial)), NULL);
    ok(ret == 0);
    ok(decrypt_packet(ingress.header_protection, aead_decrypt_fixed_key, ingress.aead, 0, &packet, &pn, &payload) == 0);
    ok(pn == 2);
    ok(sizeof(expected_payload) <= payload.len);
    ok(memcmp(expected_payload, payload.base, sizeof(expected_payload)) == 0);

    dispose_cipher(&ingress);
    dispose_cipher(&egress);
}

static void test_retry_aead(void)
{
    quicly_cid_t odcid = {{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}, 8};
    uint8_t packet_bytes[] = {0xff, 0xff, 0x00, 0x00, 0x1d, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
                              0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0xd1, 0x69, 0x26, 0xd8,
                              0x1f, 0x6f, 0x9c, 0xa2, 0x95, 0x3a, 0x8a, 0xa4, 0x57, 0x5e, 0x1e, 0x49};

    /* decode (see `test_vector` for the rationale of overwriting the version) */
    quicly_decoded_packet_t decoded;
    size_t off = 0, decoded_len = quicly_decode_packet(&quic_ctx, &decoded, packet_bytes, sizeof(packet_bytes), &off);
    ok(decoded_len == sizeof(packet_bytes));
    ok(off == sizeof(packet_bytes));

    /* decrypt */
    ptls_aead_context_t *retry_aead = create_retry_aead(&quic_ctx, QUICLY_PROTOCOL_VERSION_DRAFT29, 0);
    ok(validate_retry_tag(&decoded, &odcid, retry_aead));
    ptls_aead_free(retry_aead);
}

static void test_transport_parameters(void)
{
    quicly_transport_parameters_t decoded;

    static const uint8_t valid_bytes[] = {0x05, 0x04, 0x80, 0x10, 0x00, 0x00, 0x06, 0x04, 0x80, 0x10, 0x00, 0x00,
                                          0x07, 0x04, 0x80, 0x10, 0x00, 0x00, 0x04, 0x04, 0x81, 0x00, 0x00, 0x00,
                                          0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x08, 0x01, 0x0a, 0x0a, 0x01, 0x0a};
    memset(&decoded, 0x55, sizeof(decoded));
    ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, valid_bytes, valid_bytes + sizeof(valid_bytes)) ==
       0);
    ok(decoded.max_stream_data.bidi_local = 0x100000);
    ok(decoded.max_stream_data.bidi_remote = 0x100000);
    ok(decoded.max_stream_data.uni = 0x100000);
    ok(decoded.max_data == 0x1000000);
    ok(decoded.max_idle_timeout == 30000);
    ok(decoded.max_streams_bidi == 10);
    ok(decoded.max_streams_uni == 0);
    ok(decoded.ack_delay_exponent == 10);
    ok(decoded.max_ack_delay == 25);
    ok(decoded.active_connection_id_limit == QUICLY_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT);
    ok(!decoded.disable_active_migration);

    { /* preserve remembered peer limits and clamp local handshake/ticket limits to storage capacity */
        quicly_transport_parameters_t invalid_params = quicly_spec_context.transport_params;
        invalid_params.active_connection_id_limit = 1;
        ptls_buffer_t invalid_buf;
        ptls_buffer_init(&invalid_buf, "", 0);
        ok(quicly_encode_transport_parameter_list(&invalid_buf, &invalid_params, NULL, NULL, NULL, NULL, 0) == PTLS_ERROR_LIBRARY);
        ptls_buffer_dispose(&invalid_buf);

        const uint64_t configured_limits[] = {
            QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,    QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT, 0, 1, 2,
            QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT + 4};
        const uint64_t expected_peer_limits[] = {QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,
                                                 QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,
                                                 QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,
                                                 0,
                                                 2,
                                                 QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT + 4};
        const uint64_t expected_local_limits[] = {QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,
                                                  QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,
                                                  QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT,
                                                  QUICLY_MIN_ACTIVE_CONNECTION_ID_LIMIT,
                                                  2,
                                                  QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT};
        ptls_buffer_t auth_data[PTLS_ELEMENTSOF(configured_limits)];

        for (size_t i = 0; i != PTLS_ELEMENTSOF(configured_limits); ++i) {
            quicly_context_t ctx = i == 1 ? quicly_performant_context : quicly_spec_context;
            if (i >= 2)
                ctx.transport_params.active_connection_id_limit = configured_limits[i];
            ptls_buffer_init(&auth_data[i], "", 0);

            if (expected_peer_limits[i] != 0) {
                ptls_buffer_t encoded;
                ptls_buffer_init(&encoded, "", 0);
                ok(quicly_encode_transport_parameter_list(&encoded, &ctx.transport_params, NULL, NULL, NULL, NULL, 0) == 0);
                ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, encoded.base,
                                                          encoded.base + encoded.off) == 0);
                ok(decoded.active_connection_id_limit == expected_peer_limits[i]);
                ptls_buffer_dispose(&encoded);
            }

            ok(quicly_build_session_ticket_auth_data(&auth_data[i], &ctx) == 0);
            const uint8_t *src = auth_data[i].base, *end = src + auth_data[i].off;
            uint64_t len = quicly_decodev(&src, end);
            ok(len == end - src);
            quicly_transport_parameters_t authenticated;
            ok(quicly_decode_transport_parameter_list(&authenticated, NULL, NULL, NULL, NULL, src, end) == 0);
            ok(authenticated.active_connection_id_limit == expected_local_limits[i]);
        }
        if (QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT != 2)
            ok(auth_data[4].off != auth_data[5].off || memcmp(auth_data[4].base, auth_data[5].base, auth_data[4].off) != 0);
        for (size_t i = 0; i != PTLS_ELEMENTSOF(auth_data); ++i)
            ptls_buffer_dispose(&auth_data[i]);
    }

    { /* zero initial_max_path_id still advertises multipath support */
        static const uint8_t zero_path_limit[] = {QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_PATH_ID, 1, 0};
        memset(&decoded, 0x55, sizeof(decoded));
        ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, zero_path_limit,
                                                  zero_path_limit + sizeof(zero_path_limit)) == 0);
        ok(decoded.enable_multipath);
        ok(decoded.initial_max_path_id == 0);

        quicly_cid_t scid = {.len = 8};
        quicly_transport_parameters_t over_limit = quicly_spec_context.transport_params;
        over_limit.enable_multipath = 1;
        over_limit.initial_max_path_id = QUICLY_MAX_PATH_ID + 1;
        ptls_buffer_t over_buf;
        ptls_buffer_init(&over_buf, "", 0);
        ok(quicly_encode_transport_parameter_list(&over_buf, &over_limit, NULL, &scid, NULL, NULL, 0) == PTLS_ERROR_LIBRARY);
        ptls_buffer_dispose(&over_buf);

        /* peer limit > 255 decodes cleanly and is omitted when re-encoded for 0-RTT resumption */
        static const uint8_t peer_256[] = {QUICLY_TRANSPORT_PARAMETER_ID_INITIAL_MAX_PATH_ID, 2, 0x41, 0x00};
        quicly_transport_parameters_t peer_decoded, resumed_decoded;
        ok(quicly_decode_transport_parameter_list(&peer_decoded, NULL, NULL, NULL, NULL, peer_256, peer_256 + sizeof(peer_256)) ==
           0);
        ok(peer_decoded.enable_multipath && peer_decoded.initial_max_path_id == 256);
        ptls_buffer_init(&over_buf, "", 0);
        ok(quicly_encode_transport_parameter_list(&over_buf, &peer_decoded, NULL, NULL, NULL, NULL, 0) == 0 && over_buf.off > 0);
        ok(quicly_decode_transport_parameter_list(&resumed_decoded, NULL, NULL, NULL, NULL, over_buf.base,
                                                  over_buf.base + over_buf.off) == 0);
        ok(!resumed_decoded.enable_multipath && resumed_decoded.initial_max_path_id == 0);
        ptls_buffer_dispose(&over_buf);
    }

    static const uint8_t dup_bytes[] = {0x05, 0x04, 0x80, 0x10, 0x00, 0x00, 0x05, 0x04, 0x80, 0x10, 0x00, 0x00};
    memset(&decoded, 0x55, sizeof(decoded));
    ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, dup_bytes, dup_bytes + sizeof(dup_bytes)) ==
       QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER);
}

typedef struct st_test_multipath_aead_t {
    ptls_aead_context_t super;
    uint8_t iv[PTLS_MAX_IV_SIZE];
} test_multipath_aead_t;

static void test_multipath_aead_get_iv(ptls_aead_context_t *_ctx, void *iv)
{
    test_multipath_aead_t *ctx = (void *)_ctx;
    memcpy(iv, ctx->iv, ctx->super.algo->iv_size);
}

static void test_multipath_aead_set_iv(ptls_aead_context_t *_ctx, const void *iv)
{
    test_multipath_aead_t *ctx = (void *)_ctx;
    memcpy(ctx->iv, iv, ctx->super.algo->iv_size);
}

static void test_multipath_nonce(void)
{
    ptls_aead_algorithm_t short_algo = {.iv_size = 11}, minimum_algo = {.iv_size = 12}, long_algo = {.iv_size = PTLS_MAX_IV_SIZE};
    ptls_cipher_suite_t short_cipher = {.aead = &short_algo}, minimum_cipher = {.aead = &minimum_algo},
                        long_cipher = {.aead = &long_algo};
    ok(!is_multipath_cipher_compatible(&short_cipher));
    ok(is_multipath_cipher_compatible(&minimum_cipher));
    ok(is_multipath_cipher_compatible(&long_cipher));

    test_multipath_aead_t ctx = {
        .super = {.algo = &long_algo, .do_get_iv = test_multipath_aead_get_iv, .do_set_iv = test_multipath_aead_set_iv}};
    memset(ctx.iv, 0x5a, sizeof(ctx.iv));
    xor_path_id_iv(&ctx.super, 0x01020304);
    size_t off = sizeof(ctx.iv) - 12;
    for (size_t i = 0; i < off; ++i)
        ok(ctx.iv[i] == 0x5a);
    ok(ctx.iv[off] == (uint8_t)(0x5a ^ 1));
    ok(ctx.iv[off + 1] == (uint8_t)(0x5a ^ 2));
    ok(ctx.iv[off + 2] == (uint8_t)(0x5a ^ 3));
    ok(ctx.iv[off + 3] == (uint8_t)(0x5a ^ 4));
    for (size_t i = off + 4; i < sizeof(ctx.iv); ++i)
        ok(ctx.iv[i] == 0x5a);
    xor_path_id_iv(&ctx.super, 0x01020304);
    for (size_t i = 0; i < sizeof(ctx.iv); ++i)
        ok(ctx.iv[i] == 0x5a);
}

size_t decode_packets(quicly_decoded_packet_t *decoded, struct iovec *raw, size_t cnt)
{
    size_t ri, dc = 0;

    for (ri = 0; ri != cnt; ++ri) {
        size_t off = 0;
        do {
            size_t dl = quicly_decode_packet(&quic_ctx, decoded + dc, raw[ri].iov_base, raw[ri].iov_len, &off);
            assert(dl != SIZE_MAX);
            ++dc;
        } while (off != raw[ri].iov_len);
    }

    return dc;
}

int buffer_is(ptls_buffer_t *buf, const char *s)
{
    return buf->off == strlen(s) && memcmp(buf->base, s, buf->off) == 0;
}

static size_t transmit_with_ecn(quicly_conn_t *src, quicly_conn_t *dst, uint8_t ecn)
{
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[32];
    uint8_t datagramsbuf[PTLS_ELEMENTSOF(datagrams) * quicly_get_context(src)->transport_params.max_udp_payload_size];
    size_t num_datagrams, i;
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 2];
    quicly_error_t ret;

    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ret = quicly_send(src, &destaddr, &srcaddr, datagrams, &num_datagrams, datagramsbuf, sizeof(datagramsbuf));
    ok(ret == 0);

    if (num_datagrams != 0) {
        size_t num_packets = decode_packets(decoded, datagrams, num_datagrams);
        for (i = 0; i != num_packets; ++i) {
            decoded[i].ecn = ecn;
            ret = quicly_receive(dst, NULL, &fake_address.sa, decoded + i);
            ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
        }
    }

    return num_datagrams;
}

size_t transmit(quicly_conn_t *src, quicly_conn_t *dst)
{
    return transmit_with_ecn(src, dst, 0);
}

static void exchange_until_idle(quicly_conn_t *c1, quicly_conn_t *c2)
{
    while (1) {
        int64_t t1 = quicly_get_first_timeout(c1), t2 = quicly_get_first_timeout(c2), tmin = t1 <= t2 ? t1 : t2;
        if (tmin > quic_now) {
            if (tmin - quic_now > QUICLY_DEFAULT_MAX_ACK_DELAY)
                break;
            quic_now = tmin;
        }
        if (t1 <= t2) {
            transmit(c1, c2);
        } else {
            transmit(c2, c1);
        }
    }
}

int max_data_is_equal(quicly_conn_t *client, quicly_conn_t *server)
{
    uint64_t client_sent, client_consumed;
    uint64_t server_sent, server_consumed;

    quicly_get_max_data(client, NULL, &client_sent, &client_consumed, NULL);
    quicly_get_max_data(server, NULL, &server_sent, &server_consumed, NULL);

    if (client_sent != server_consumed)
        return 0;
    if (server_sent != client_consumed)
        return 0;

    return 1;
}

static void test_next_packet_number(void)
{
    /* prefer lower in case the distance in both directions are equal; see https://github.com/quicwg/base-drafts/issues/674 */
    uint64_t n = quicly_determine_packet_number(0xc0, 8, 0x139);
    ok(n == 0xc0);
    n = quicly_determine_packet_number(0xc0, 8, 0x140);
    ok(n == 0x1c0);
    n = quicly_determine_packet_number(0x9b32, 16, 0xa82f30eb);
    ok(n == 0xa82f9b32);

    n = quicly_determine_packet_number(31, 16, 65259);
    ok(n == 65567);
}

static void test_address_token_codec_decode(ptls_aead_context_t *dec, const void *encrypted, size_t encrypted_len)
{
    quicly_address_token_plaintext_t output;
    const char *err_desc;

    ptls_openssl_random_bytes(&output, sizeof(output));

    ok(quicly_decrypt_address_token(dec, &output, encrypted, encrypted_len, 0, &err_desc) == 0);
    ok(output.type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY);
    ok(output.issued_at == 234);
    ok(output.remote.sa.sa_family == AF_INET);
    ok(output.remote.sin.sin_addr.s_addr == htonl(0x7f000001));
    ok(output.remote.sin.sin_port == htons(443));
    ok(quicly_cid_is_equal(&output.retry.original_dcid, ptls_iovec_init("abcdefgh", 8)));
    ok(quicly_cid_is_equal(&output.retry.client_cid, ptls_iovec_init("01234", 5)));
    ok(quicly_cid_is_equal(&output.retry.server_cid, ptls_iovec_init("abcdef0123456789", 16)));
    ok(output.appdata.len == 11);
    ok(memcmp(output.appdata.bytes, "hello world", 11) == 0);
}

static void test_address_token_codec(void)
{
    static const uint8_t zero_key[PTLS_MAX_SECRET_SIZE] = {0};
    ptls_aead_context_t *enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, zero_key, ""),
                        *dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, zero_key, "");

    quicly_address_token_plaintext_t input, output;
    ptls_buffer_t buf;
    const char *err_desc;

    { /* test hard-coded sample */
        static const uint8_t sample[] = {0x00, 0x39, 0xef, 0x13, 0x9a, 0xe1, 0xaa, 0x28, 0x51, 0x62, 0xf6, 0xd8, 0xc8, 0x93, 0x6a,
                                         0xdf, 0xd1, 0xbe, 0xa4, 0xb5, 0x99, 0xb9, 0xd7, 0x99, 0x02, 0xe3, 0x9e, 0xf2, 0xd0, 0x30,
                                         0x0b, 0x80, 0xcf, 0x66, 0xc4, 0x69, 0xc3, 0x86, 0x69, 0x92, 0xef, 0x3f, 0xd9, 0x64, 0x4b,
                                         0x6e, 0x9e, 0x16, 0x3a, 0x4d, 0xb6, 0x2c, 0xfc, 0x99, 0xe4, 0x46, 0x88, 0x7a, 0x73, 0x0d,
                                         0x69, 0x0e, 0xfb, 0xbf, 0x0e, 0x7c, 0xe3, 0x2d, 0x78, 0xf3, 0x90, 0xf6, 0xfd, 0xa4, 0x5e,
                                         0x71, 0x23, 0x3a, 0x15, 0xf2, 0x5f, 0xa6, 0x9e, 0x36, 0x13, 0x69, 0x53, 0xc1};
        test_address_token_codec_decode(dec, sample, sizeof(sample));
    }

    /* encrypt and decrypt */
    input = (quicly_address_token_plaintext_t){QUICLY_ADDRESS_TOKEN_TYPE_RETRY, 234};
    input.remote.sin.sin_family = AF_INET;
    input.remote.sin.sin_addr.s_addr = htonl(0x7f000001);
    input.remote.sin.sin_port = htons(443);
    quicly_set_cid(&input.retry.original_dcid, ptls_iovec_init("abcdefgh", 8));
    quicly_set_cid(&input.retry.client_cid, ptls_iovec_init("01234", 5));
    quicly_set_cid(&input.retry.server_cid, ptls_iovec_init("abcdef0123456789", 16));
    strcpy((char *)input.appdata.bytes, "hello world");
    input.appdata.len = strlen((char *)input.appdata.bytes);
    ptls_buffer_init(&buf, "", 0);
    ok(quicly_encrypt_address_token(ptls_openssl_random_bytes, enc, &buf, 0, &input) == 0);
    test_address_token_codec_decode(dec, buf.base, buf.off);

    /* failure to decrypt a Retry token is a hard error */
    ptls_openssl_random_bytes(&output, sizeof(output));
    buf.base[buf.off - 1] ^= 0x80;
    ok(quicly_decrypt_address_token(dec, &output, buf.base, buf.off, 0, &err_desc) == QUICLY_TRANSPORT_ERROR_INVALID_TOKEN);
    buf.base[buf.off - 1] ^= 0x80;

    /* failure to decrypt a token that is not a Retry is a soft error */
    ptls_openssl_random_bytes(&output, sizeof(output));
    buf.base[0] ^= 0x80;
    ok(quicly_decrypt_address_token(dec, &output, buf.base, buf.off, 0, &err_desc) == PTLS_ALERT_DECODE_ERROR);
    buf.base[0] ^= 0x80;

    /* round-trip of an IPv6 address with a non-zero scope_id (see h2o/h2o#3640) */
    static const uint8_t addr6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    input = (quicly_address_token_plaintext_t){QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION, 345};
    input.remote.sin6.sin6_family = AF_INET6;
    memcpy(&input.remote.sin6.sin6_addr, addr6, 16);
    input.remote.sin6.sin6_scope_id = 5;
    input.remote.sin6.sin6_port = htons(443);
    strcpy((char *)input.resumption.bytes, "hello world");
    input.resumption.len = strlen((char *)input.resumption.bytes);
    ptls_buffer_dispose(&buf);
    ptls_buffer_init(&buf, "", 0);
    ok(quicly_encrypt_address_token(ptls_openssl_random_bytes, enc, &buf, 0, &input) == 0);
    ptls_openssl_random_bytes(&output, sizeof(output));
    ok(quicly_decrypt_address_token(dec, &output, buf.base, buf.off, 0, &err_desc) == 0);
    ok(output.type == QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION);
    ok(output.remote.sa.sa_family == AF_INET6);
    ok(memcmp(output.remote.sin6.sin6_addr.s6_addr, addr6, 16) == 0);
    ok(output.remote.sin6.sin6_scope_id == 5);
    ok(output.remote.sin6.sin6_port == htons(443));
    ok(output.resumption.len == 11);
    ok(memcmp(output.resumption.bytes, "hello world", 11) == 0);

    ptls_buffer_dispose(&buf);
    ptls_aead_free(enc);
    ptls_aead_free(dec);
}

static void do_test_record_receipt(size_t epoch)
{
    struct st_quicly_pn_space_t *space =
        alloc_pn_space(sizeof(*space), epoch == QUICLY_EPOCH_1RTT ? QUICLY_DEFAULT_PACKET_TOLERANCE : 1);
    uint64_t pn = 0, out_of_order_cnt = 0;
    int64_t now = 12345, send_ack_at = INT64_MAX;

    if (epoch == QUICLY_EPOCH_1RTT) {
        /* 2nd packet triggers an ack */
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now + QUICLY_DELAYED_ACK_TIMEOUT);
        now += 1;
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now);
        now += 1;
    } else {
        /* every packet triggers an ack */
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now);
        now += 1;
    }

    /* reset */
    space->unacked_count = 0;
    send_ack_at = INT64_MAX;

    /* ack-only packets do not elicit an ack */
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    pn++; /* gap */
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;

    /* gap triggers an ack */
    pn += 1; /* gap */
    ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == now);
    now += 1;

    /* reset */
    space->unacked_count = 0;
    send_ack_at = INT64_MAX;

    /* if 1-RTT, test ignore-order */
    if (epoch == QUICLY_EPOCH_1RTT) {
        space->reordering_threshold = 0;
        pn++; /* gap */
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now + QUICLY_DELAYED_ACK_TIMEOUT);
        now += 1;
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now);
        now += 1;
    }

    do_free_pn_space(space);
}

static void do_test_ack_frequency_ack_logic()
{
    struct st_case_row_t {
        uint64_t packet_number;
        uint8_t send_ack;
        uint64_t expected_smallest_unreported_missing_after_receipt;
        int is_ack_only;
        uint64_t advance_time_by;
    };

    struct st_test_case {
        const struct st_case_row_t *rows;
        size_t rows_count;
        uint8_t reordering_threshold;
        uint32_t packet_tolerance;
    };

    // From example 1 at https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-11#section-6.2.1
    // clang-format off
    const struct st_case_row_t example1_rows[] = {
        {0,  0, 1,  0, 1},
        {1,  0, 2,  0, 1},
        {3,  0, 2,  0, 1},
        {4,  0, 2,  0, 1},
        {5,  1, 6,  0, 1},
        {8,  0, 6,  0, 1},
        {9,  1, 7,  0, 1},
        {10, 1, 11, 0, 1},
    };
    // clang-format on
    const struct st_test_case example1 = {
        .rows = example1_rows,
        .rows_count = PTLS_ELEMENTSOF(example1_rows),
        .reordering_threshold = 3,
        .packet_tolerance = 100,
    };

    // From example 1 at https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-11#section-6.2.1
    // clang-format off
    const struct st_case_row_t example2_rows[] = {
        {0, 0, 1,  0, 1},
        {1, 0, 2,  0, 1},
        {3, 0, 2,  0, 1},
        {5, 0, 2,  0, 1},
        {6, 0, 2,  0, 1},
        {7, 1, 4,  0, 1},
        {8, 0, 4,  0, 1},
        {9, 1, 10, 0, 1},
    };
    // clang-format on
    const struct st_test_case example2 = {
        .rows = example2_rows,
        .rows_count = PTLS_ELEMENTSOF(example2_rows),
        .reordering_threshold = 5,
        .packet_tolerance = 100,
    };

    // Disable reorder threshold, test packet tolerance
    // clang-format off
    const struct st_case_row_t test_case_1_rows[] = {
        // smallest unreported is n+1 because reordering threshold is set to 0
        {1,  0, 2,  0, 1},  // No ack yet (reordering_threshold = 0, so no immediate ack for reordering)
        {2,  1, 3,  0, 1},  // Ack because we've seen 2 packets
        {3,  0, 4,  0, 1},  // No ack yet
        {4,  1, 5,  0, 1},  // Ack because we've seen 2 packets
        {5,  0, 6,  0, 1},  // ...
        {6,  1, 7,  0, 1},
        {7,  0, 8,  0, 1},
        {8,  1, 9,  0, 1},
        {9,  0, 10, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_1 = {
        .rows = test_case_1_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_1_rows),
        .reordering_threshold = 0,
        .packet_tolerance = 2,
    };

    // Test reordered packets
    // clang-format off
    const struct st_case_row_t test_case_2_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 1, 2, 0, 1}, // Ack because we've seen 3 packets
        {2, 0, 4, 0, 1}, // No ack because 2 was never considered lost
        {4, 0, 5, 0, 1},
        {5, 1, 6, 0, 1}, // Ack because we've seen 3 more packets
    };
    // clang-format on
    const struct st_test_case test_case_2 = {
        .rows = test_case_2_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_2_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 3,
    };

    // Test a declared lost packet is received
    // clang-format off
    const struct st_case_row_t test_case_3_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 1, 2, 0, 1}, // Ack because we've seen 3 packets
        {4, 1, 5, 0, 1}, // Ack because 2 is now declared lost
        {2, 1, 5, 0, 1}, // Ack because 2 was received (change outside the reordering window)
        {5, 0, 6, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_3 = {
        .rows = test_case_3_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_3_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 3,
    };

    // Test 0 is lost
    // clang-format off
    const struct st_case_row_t test_case_4_rows[] = {
        {1, 0, 0, 0, 1},
        {2, 0, 0, 0, 1},
        {3, 1, 4, 0, 1}, // Ack because 0 is now declared lost
        {0, 1, 4, 0, 1}, // Ack because 0 was received (change outside the reordering window)
    };
    // clang-format on
    const struct st_test_case test_case_4 = {
        .rows = test_case_4_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_4_rows),
        .reordering_threshold = 3,
        .packet_tolerance = 100,
    };

    // Test larget packet tolerance and reordering threshold
    // Skipped 0
    // clang-format off
    const struct st_case_row_t test_case_5_rows[] = {
        {1, 0, 0, 0, 1},
        {2, 0, 0, 0, 1},
        {3, 0, 0, 0, 1},
        {4, 0, 0, 0, 1},
        {5, 0, 0, 0, 1},
        {6, 0, 0, 0, 1},
        {7, 0, 0, 0, 1},
        {8, 0, 0, 0, 1},
        {9, 0, 0, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_5 = {
        .rows = test_case_5_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_5_rows),
        .reordering_threshold = 20,
        .packet_tolerance = 20,
    };

    // ack every packet
    // clang-format off
    const struct st_case_row_t test_case_6_rows[] = {
        {0, 1, 1,  0, 1},
        {1, 1, 2,  0, 1},
        {2, 1, 3,  0, 1},
        {3, 1, 4,  0, 1},
        {4, 1, 5,  0, 1},
        {5, 1, 6,  0, 1},
        {6, 1, 7,  0, 1},
        {7, 1, 8,  0, 1},
        {8, 1, 9,  0, 1},
        {9, 1, 10, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_6 = {
        .rows = test_case_6_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_6_rows),
        .reordering_threshold = 0,
        .packet_tolerance = 0,
    };

    // Send packets ack-eliciting packets [0,1,3]. Then send non-ack eliciting
    // packets [4..7] with `QUICLY_DELAYED_ACK_TIMEOUT` amount of time between.
    //
    // After we send an ack for PN 4, PN 2 is declared lost, and the next
    // smallest unreported missing PN is 5.
    //
    // clang-format off
    const struct st_case_row_t test_case_7_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 0, 2, 0, 1},
        {4, 0, 5, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {5, 0, 6, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {6, 0, 7, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {7, 0, 8, 1, QUICLY_DELAYED_ACK_TIMEOUT},
    };
    // clang-format on
    const struct st_test_case test_case_7 = {
        .rows = test_case_7_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_7_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 20,
    };

    // Send packets ack-eliciting packets [0,1,3]. Then send non-ack eliciting
    // packets [4] with `QUICLY_DELAYED_ACK_TIMEOUT` amount of time between.
    //
    // After we send an ack for PN 4, PN 2 is declared lost, and the next
    // smallest unreported missing PN is 5.
    //
    // Then send packet 2 as ack-eliciting packet. This should be reported right
    // away to detect spurious losses.
    //
    // clang-format off
    const struct st_case_row_t test_case_8_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 0, 2, 0, 1},
        {4, 0, 5, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {2, 1, 5, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_8 = {
        .rows = test_case_8_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_8_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 20,
    };

    // Same as the above test case, but packet 2 is non-ack-eliciting, so we
    // should not trigger and ack
    const struct st_case_row_t test_case_9_rows[] = {
        {0, 0, 1, 0, 1}, {1, 0, 2, 0, 1}, {3, 0, 2, 0, 1}, {4, 0, 5, 1, QUICLY_DELAYED_ACK_TIMEOUT}, {2, 0, 5, 1, 1},
    };
    // clang-format on
    const struct st_test_case test_case_9 = {
        .rows = test_case_9_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_9_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 20,
    };

    // clang-format off
    struct st_test_case test_cases[] = {
        example1,
        example2,
        test_case_1,
        test_case_2,
        test_case_3,
        test_case_4,
        test_case_5,
        test_case_6,
        test_case_7,
        test_case_8,
        test_case_9,
    };
    // clang-format on

    for (int i = 0; i < PTLS_ELEMENTSOF(test_cases); ++i) {
        int64_t now = 12345;
        uint64_t out_of_order_cnt = 0;
        int64_t send_ack_at = INT64_MAX;

        struct st_quicly_pn_space_t *space = alloc_pn_space(sizeof(*space), QUICLY_DEFAULT_PACKET_TOLERANCE);
        space->reordering_threshold = test_cases[i].reordering_threshold;
        space->packet_tolerance = test_cases[i].packet_tolerance;

        for (int row_idx = 0; row_idx < test_cases[i].rows_count; ++row_idx) {
            struct st_case_row_t row = test_cases[i].rows[row_idx];

            ok(record_receipt(space, row.packet_number, 0, row.is_ack_only, now, &send_ack_at, &out_of_order_cnt) == 0);
            ok(row.send_ack ? send_ack_at == now : send_ack_at > now);
            now += row.advance_time_by;
            if (send_ack_at <= now && space->ack_queue.num_ranges > 0) {
                send_ack_at = INT64_MAX;
                space->unacked_count = 0;
                update_smallest_unreported_missing_on_send_ack(&space->ack_queue, &space->largest_acked_unacked,
                                                               &space->smallest_unreported_missing, space->reordering_threshold);
            }

            ok(row.expected_smallest_unreported_missing_after_receipt == space->smallest_unreported_missing);
        }

        do_free_pn_space(space);
    }
}

static void test_record_receipt(void)
{
    do_test_record_receipt(QUICLY_EPOCH_INITIAL);
    do_test_record_receipt(QUICLY_EPOCH_1RTT);
    do_test_ack_frequency_ack_logic();
}

static void test_is_duplicate_pn(void)
{
    quicly_ranges_t ranges;

    /* at the beginning of a connection, the ack queue is empty and the first packet number being expected is zero */
    quicly_ranges_init(&ranges);
    ok(!is_duplicate_pn(&ranges, 0, 0));

    /* packets at or above the one being expected next are never duplicate */
    ok(quicly_ranges_add(&ranges, 0, 5) == 0);
    ok(!is_duplicate_pn(&ranges, 5, 5));
    ok(!is_duplicate_pn(&ranges, 6, 5));

    /* packet numbers covered by the ack queue are duplicate */
    ok(is_duplicate_pn(&ranges, 4, 5));
    ok(is_duplicate_pn(&ranges, 0, 5));

    /* packet numbers within a gap have not been received yet */
    ok(quicly_ranges_add(&ranges, 8, 11) == 0);
    ok(!is_duplicate_pn(&ranges, 5, 11));
    ok(!is_duplicate_pn(&ranges, 7, 11));
    ok(is_duplicate_pn(&ranges, 8, 11));
    ok(is_duplicate_pn(&ranges, 10, 11));
    ok(is_duplicate_pn(&ranges, 3, 11));

    /* packet numbers below the oldest range being retained are discarded, as we cannot tell if they have been processed */
    quicly_ranges_clear(&ranges);
    ok(quicly_ranges_add(&ranges, 8, 11) == 0);
    ok(is_duplicate_pn(&ranges, 7, 11));
    ok(is_duplicate_pn(&ranges, 0, 11));

    /* ditto, when the ack queue has been emptied by the peer acknowledging our ACKs */
    quicly_ranges_clear(&ranges);
    ok(is_duplicate_pn(&ranges, 10, 11));
    ok(!is_duplicate_pn(&ranges, 11, 11));

    quicly_ranges_clear(&ranges);
}

static void test_record_pn(void)
{
    quicly_ranges_t ranges;
    int is_out_of_order;
    quicly_error_t ret = 0;

    quicly_ranges_init(&ranges);

    /* record discontiguous packet numbers 0, 2, ..., so that the number of ranges exceeds the maximum by one */
    for (uint64_t pn = 0; pn <= QUICLY_MAX_ACK_BLOCKS * 2; pn += 2)
        if ((ret = record_pn(&ranges, pn, &is_out_of_order)) != 0)
            break;
    ok(ret == 0);

    /* the oldest range is dropped, and the newest ones including the one just being recorded are retained */
    ok(ranges.num_ranges == QUICLY_MAX_ACK_BLOCKS);
    ok(ranges.ranges[0].start == 2);
    ok(ranges.ranges[ranges.num_ranges - 1].start == QUICLY_MAX_ACK_BLOCKS * 2);

    quicly_ranges_clear(&ranges);
}

static void test_ack_frequency(void)
{
    quicly_conn_t *client, *server;
    quicly_stream_t *client_stream, *server_stream;
    quicly_error_t ret;

    quicly_context_t ctx = quic_ctx;
    ctx.ack_frequency = 1024; // every rtt

    { /* connect */
        quicly_address_t dest, src;
        struct iovec raw;
        uint8_t rawbuf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &dest, &src, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        ok(decode_packets(&decoded, &raw, 1) == 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL);
        ok(ret == 0);
        transmit(server, client);
    }

    ret = quicly_open_stream(client, &client_stream, 0);
    assert(ret == 0);
    ret = quicly_streambuf_egress_write(client_stream, "hello", 5);
    assert(ret == 0);

    transmit(client, server);
    transmit(server, client);

    /* reset one stream in both directions and close on the client-side */
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);

    // Set some losses to trigger ack frequency path
    server->path_spaces[0]->cc.num_loss_episodes = 5;
    client->path_spaces[0]->cc.num_loss_episodes = 5;

    ok(server->application->super.reordering_threshold == 1);
    ok(client->application->super.reordering_threshold == 1);

    const char *testdata = "hello";
    const int testdata_len = strlen(testdata);

    const int steps = 80;
    for (int i = 0; i < steps; i++) {
        quicly_stream_t *s = server_stream;
        if (i > steps / 2)
            s = client_stream;

        ret = quicly_streambuf_egress_write(s, testdata, testdata_len);
        assert(ret == 0);

        ptls_iovec_t buf = quicly_streambuf_ingress_get(s);
        quicly_streambuf_ingress_shift(s, buf.len);

        transmit(server, client);
        transmit(client, server);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    }

    // Both sides have updated their reordering thresholds
    ok(server->application->super.reordering_threshold == 3);
    ok(client->application->super.reordering_threshold == 3);

    quicly_free(client);
    quicly_free(server);
}

static void test_cid(void)
{
    subtest("received cid", test_received_cid);
    subtest("local cid", test_local_cid);
}

/**
 * test if quicly_accept correctly rejects a non-decryptable Initial packet with QUICLY_ERROR_DECRYPTION_FAILED
 */
static void test_nondecryptable_initial(void)
{
#define PACKET_LEN 1280
#define HEADER_LEN 18
#define LEN_HIGH (((PACKET_LEN - HEADER_LEN) & 0xff00) >> 8)
#define LEN_LOW ((PACKET_LEN - HEADER_LEN) & 0xff)
    uint8_t header[HEADER_LEN] = {
        /* first byte for Initial: 0b1100???? */
        0xc5,
        /* version (29) */
        0xff,
        0x00,
        0x00,
        0x1d,
        /* DCID len */
        0x08,
        /* DCID */
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
        /* SCID len */
        0x00,
        /* SCID does not appear */
        /* token length */
        0x00,
        /* token does not appear */
        /* length */
        (0x40 | LEN_HIGH),
        LEN_LOW,
    };
    quicly_conn_t *server;
    uint8_t packetbuf[PACKET_LEN];
    struct iovec packet = {.iov_base = packetbuf, .iov_len = sizeof(packetbuf)};
    size_t num_decoded;
    quicly_decoded_packet_t decoded;
    quicly_error_t ret;

    /* create an Initial packet, with its payload all set to zero */
    memcpy(packetbuf, header, sizeof(header));
    memset(packetbuf + sizeof(header), 0, sizeof(packetbuf) - sizeof(header));
    num_decoded = decode_packets(&decoded, &packet, 1);
    ok(num_decoded == 1);

    /* decryption should fail */
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL);
    ok(ret == QUICLY_ERROR_DECRYPTION_FAILED);
#undef PACKET_LEN
#undef HEADER_LEN
#undef LEN_HIGH
#undef LEN_LOW
}

static void test_set_cc(void)
{
    quicly_conn_t *conn;
    quicly_error_t ret;

    ret = quicly_connect(&conn, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL, NULL);
    ok(ret == 0);

    quicly_stats_t stats;

    // init CC with pico
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // pico to pico
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // reno to pico
    quicly_set_cc(conn, &quicly_cc_type_reno);
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // cubic to pico
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // pico to reno
    quicly_set_cc(conn, &quicly_cc_type_pico);
    quicly_set_cc(conn, &quicly_cc_type_reno);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "reno") == 0);

    // pico to cubic
    quicly_set_cc(conn, &quicly_cc_type_pico);
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "cubic") == 0);

    // reno to cubic
    quicly_set_cc(conn, &quicly_cc_type_reno);
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "cubic") == 0);

    // cubic to reno
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    quicly_set_cc(conn, &quicly_cc_type_reno);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "reno") == 0);
}

static void test_cc_accel_context(void)
{
    quicly_init_cc_t *const policies[] = {&quicly_cc_cubic_init, &quicly_cc_cuback_init};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(policies); ++i) {
        quicly_context_t ctx = quic_ctx;
        ctx.egress[0].cc.init_cc = policies[i];
        ctx.egress[0].cc.abba = 1;
        quicly_conn_t *conn;
        ok(quicly_connect(&conn, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                          NULL) == 0);
        ok(conn->path_spaces[0]->cc.conf == &ctx.egress[0].cc && conn->path_spaces[0]->cc.conf->abba);
        ok(conn->path_spaces[0]->cc.state.pico.abba.high.cwnd == 0);

        /* Path promotion uses configured policy and discards the old path's measurements. */
        quicly_cc_conf_t stale_conf = ctx.egress[0].cc;
        stale_conf.abba = 0;
        conn->path_spaces[0]->cc.conf = &stale_conf;
        conn->path_spaces[0]->cc.state.pico.abba.high.cwnd = 100000;
        quicly_rtt_update(&conn->path_spaces[0]->loss.rtt, 20, 0, conn->stash.now);
        ok(quicly_rtt_get_floor(&conn->path_spaces[0]->loss.rtt) == 20);
        size_t candidate = encode_flat_path_index(0, 1);
        ok(new_path(conn, candidate, 0, &fake_address.sa, NULL) == 0);
        ok(promote_path(conn, candidate) == 0);
        ok(conn->path_spaces[0]->cc.conf == &ctx.egress[0].cc && conn->path_spaces[0]->cc.conf->abba);
        ok(conn->path_spaces[0]->cc.type->cc_init == policies[i]);
        ok(conn->path_spaces[0]->cc.state.pico.abba.high.cwnd == 0);
        ok(conn->path_spaces[0]->loss.rtt.latest == 0);
        ok(conn->path_spaces[0]->loss.rtt.floor.newest_sample_until == 0);
        ok(quicly_rtt_get_floor(&conn->path_spaces[0]->loss.rtt) == 20); /* initial estimate inherited from the old path */
        quicly_rtt_update(&conn->path_spaces[0]->loss.rtt, 80, 0, conn->stash.now);
        ok(quicly_rtt_get_floor(&conn->path_spaces[0]->loss.rtt) == 80);
        quicly_free(conn);
    }
}

void test_ecn_index_from_bits(void)
{
    ok(get_ecn_index_from_bits(1) == 1);
    ok(get_ecn_index_from_bits(2) == 0);
    ok(get_ecn_index_from_bits(3) == 2);
}

static void test_l4s_context(void)
{
    static const uint8_t expected_bits[] = {[QUICLY_ECN_MODE_OFF] = 0, [QUICLY_ECN_MODE_CLASSIC] = 2, [QUICLY_ECN_MODE_L4S] = 1};
    for (int mode = QUICLY_ECN_MODE_OFF; mode <= QUICLY_ECN_MODE_L4S; ++mode) {
        quicly_context_t ctx = quic_ctx;
        ctx.egress[0].cc.init_cc = &quicly_cc_cuback_init;
        ctx.egress[0].ecn = mode;
        ctx.egress[0].pacing = 1;
        quicly_conn_t *conn;
        ok(quicly_connect(&conn, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                          NULL) == 0);
        ok(is_l4s(conn) == (mode == QUICLY_ECN_MODE_L4S));
        ok(quicly_send_get_ecn_bits(conn) == expected_bits[mode]);
        quicly_free(conn);
    }
}

static void test_l4s_feedback(void)
{
    quicly_context_t ctx = quic_ctx;
    ctx.egress[0].cc.init_cc = &quicly_cc_cuback_init;
    ctx.egress[0].ecn = QUICLY_ECN_MODE_L4S;
    ctx.egress[0].pacing = 1;
    quicly_conn_t *conn;
    ok(quicly_connect(&conn, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                      NULL) == 0);
    conn->path_spaces[0]->packet_number = 100;
    quicly_ack_frame_t frame = {.largest_acknowledged = 20, .ecn_counts = {0, 19, 1}};
    quicly_cc_ecn_counts_t counts;
    handle_ecn_feedback(conn, conn->path_spaces[0], QUICLY_EPOCH_1RTT, &frame, 1, &counts);
    ok(counts.total == 20 && counts.ce == 1 && conn->egress.ecn.state == QUICLY_ECN_ON);
    ok(conn->super.stats.num_packets.acked_ecn_counts[1] == 19);
    ok(conn->super.stats.num_packets.acked_ecn_counts[2] == 1);
    conn->path_spaces[0]->loss.largest_acked_packet_plus1.per_epoch[QUICLY_EPOCH_1RTT] =
        21; /* as the loss detection engine records */

    /* ACKs that do not advance the largest acknowledged are ignored, whether the counters advance or regress. */
    frame.ecn_counts[2] = 2;
    handle_ecn_feedback(conn, conn->path_spaces[0], QUICLY_EPOCH_1RTT, &frame, 1, &counts);
    ok(counts.total == 0 && counts.ce == 0 && conn->egress.ecn.state == QUICLY_ECN_ON);
    frame.largest_acknowledged = 15; /* newly acknowledging a range omitted by newer ACKs */
    frame.ecn_counts[1] = 14;
    frame.ecn_counts[2] = 0;
    handle_ecn_feedback(conn, conn->path_spaces[0], QUICLY_EPOCH_1RTT, &frame, 1, &counts);
    ok(counts.total == 0 && counts.ce == 0 && conn->egress.ecn.state == QUICLY_ECN_ON);

    /* Counter regression in an ACK that advances the largest acknowledged fails validation. */
    frame.largest_acknowledged = 21;
    frame.ecn_counts[1] = 19;
    frame.ecn_counts[2] = 0;
    handle_ecn_feedback(conn, conn->path_spaces[0], QUICLY_EPOCH_1RTT, &frame, 1, &counts);
    ok(counts.total == 0 && counts.ce == 0 && conn->egress.ecn.state == QUICLY_ECN_OFF);
    ok(quicly_send_get_ecn_bits(conn) == 0);
    quicly_free(conn);

    for (int is_ack_ecn = 0; is_ack_ecn != 2; ++is_ack_ecn) {
        ok(quicly_connect(&conn, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                          NULL) == 0);
        conn->path_spaces[0]->packet_number = 100;
        frame = (quicly_ack_frame_t){.largest_acknowledged = 20, .ecn_counts = {20, 0, 0}};
        handle_ecn_feedback(conn, conn->path_spaces[0], QUICLY_EPOCH_1RTT, &frame, is_ack_ecn, &counts);
        ok(counts.total == 0 && conn->egress.ecn.state == QUICLY_ECN_OFF); /* missing feedback or ECT(1) rewritten to ECT(0) */
        quicly_free(conn);
    }
}

static void test_l4s_transfer(void)
{
    quicly_context_t ctx = quic_ctx;
    ctx.egress[0].cc.init_cc = &quicly_cc_cuback_init;
    ctx.egress[0].ecn = QUICLY_ECN_MODE_L4S;
    ctx.egress[0].pacing = 1;
    quicly_conn_t *client, *server;
    ok(quicly_connect(&client, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                      NULL) == 0);
    quicly_address_t dest, src;
    struct iovec datagrams[8];
    uint8_t buf[8 * 1500];
    size_t count = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &dest, &src, datagrams, &count, buf, sizeof(buf)) == 0);
    ok(count == 1);
    quicly_decoded_packet_t decoded[8];
    ok(decode_packets(decoded, datagrams, count) == 1);
    decoded[0].ecn = quicly_send_get_ecn_bits(client);
    ok(decoded[0].ecn == 1);
    ok(quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL, NULL) == 0);
    for (int i = 0; i != 10; ++i) {
        quic_now += 20;
        transmit(server, client);
        transmit_with_ecn(client, server, 1);
    }
    ok(quicly_connection_is_ready(client));
    ok(client->egress.ecn.state == QUICLY_ECN_ON && is_l4s(client));
    ok(client->super.stats.num_packets.acked_ecn_counts[1] != 0);

    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    uint8_t data[50000] = {0};
    ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
    quic_now += 20;
    ok(transmit_with_ecn(client, server, 3) > 0);
    quic_now += 20;
    ok(transmit(server, client) > 0);
    ok(client->super.stats.num_packets.acked_ecn_counts[2] != 0);
    /* the CE marks have reached the congestion controller */
    ok(client->path_spaces[0]->cc.num_ecn_loss_episodes == 1);
    ok(quicly_send_get_ecn_bits(client) == 1);
    quicly_free(client);
    quicly_free(server);
}

static void test_resume_sendrate(void)
{
    quicly_path_space_t ps = {0};
    uint64_t rate;
    uint32_t rtt;
    const struct {
        float minimum;
        uint32_t stored;
    } cases[] = {{0.001f, 1}, {0.25f, 1}, {1, 1}, {1.25f, 2}, {250, 250}};

    quicly_ratemeter_init(&ps.ratemeter);
    ps.loss.rtt.minimum = 0.25f;
    calc_resume_sendrate(&ps, &rate, &rtt);
    ok(rate == 0 && rtt == 0);

    quicly_ratemeter_enter_cc_limited(&ps.ratemeter, 0);
    quicly_ratemeter_on_ack(&ps.ratemeter, 1000, 1000, 0);
    quicly_ratemeter_on_ack(&ps.ratemeter, 1050, 51000, 1);
    for (size_t i = 0; i < PTLS_ELEMENTSOF(cases); ++i) {
        ps.loss.rtt.minimum = cases[i].minimum;
        calc_resume_sendrate(&ps, &rate, &rtt);
        ok(rate == 1000000);
        ok(rtt == cases[i].stored);
    }
}

static void test_jumpstart_cwnd(void)
{
    ok(derive_jumpstart_cwnd(UINT32_MAX, 1200, 250, 1000000, 250) == 250000);
    ok(derive_jumpstart_cwnd(UINT32_MAX, 1200, 0.25f, 1000000, 1) == 250);
    ok(derive_jumpstart_cwnd(UINT32_MAX, 1200, 1.25f, 1000000, 2) == 1250);
    ok(derive_jumpstart_cwnd(UINT32_MAX, 1200, 250, 1000000, 400) == 250000); /* if RTT increases, CWND stays same */
    ok(derive_jumpstart_cwnd(UINT32_MAX, 1200, 250, 1000000, 125) == 125000); /* if RTT decreses, CWND is reduced proportionally */

    ok(derive_jumpstart_cwnd(64, 1250, 250, 1000000, 250) == 80000);
}

static void test_setup_connected_peers(quicly_conn_t **client, quicly_conn_t **server)
{
    quicly_address_t dest, src;
    struct iovec datagrams[8];
    uint8_t packetsbuf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 4];
    size_t num_datagrams, num_decoded;
    quicly_error_t ret;

    ret = quicly_connect(client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL, NULL);
    ok(ret == 0);
    num_datagrams = sizeof(datagrams);
    ret = quicly_send(*client, &dest, &src, datagrams, &num_datagrams, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    num_decoded = decode_packets(decoded, datagrams, 1);
    ok(num_decoded == 1);
    ret = quicly_accept(server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL, NULL);
    ok(ret == 0);
    num_datagrams = transmit(*server, *client);
    ok(num_datagrams > 0);
    ok(quicly_get_state(*client) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_state(*server) == QUICLY_STATE_CONNECTED);
    exchange_until_idle(*client, *server);
}

/**
 * sends stream data from `src` to `dst`, returning the path ID of the DCID being used
 */
static uint64_t send_and_get_dcid_path_id(quicly_conn_t *src, quicly_conn_t *dst)
{
    quicly_stream_t *stream;
    ok(quicly_open_stream(src, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "hello", 5) == 0);

    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[4];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(src, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    assert(num_datagrams != 0);

    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 2];
    size_t num_packets = decode_packets(decoded, datagrams, num_datagrams);
    uint64_t path_id = decoded[0].cid.dest.plaintext.path_id;
    for (size_t i = 0; i < num_packets; ++i)
        ok(quicly_receive(dst, NULL, &fake_address.sa, decoded + i) == 0);

    return path_id;
}

/**
 * CID encryptor that wraps the default one, reporting `rotating_key_generation` as the generation of the key
 */
static quicly_cid_encryptor_t *rotating_inner;
static uint64_t rotating_key_generation;

static void rotating_encrypt_cid(quicly_cid_encryptor_t *self, quicly_cid_t *encrypted, void *stateless_reset_token,
                                 const quicly_cid_plaintext_t *plaintext)
{
    rotating_inner->encrypt_cid(rotating_inner, encrypted, stateless_reset_token, plaintext);
}

static size_t rotating_decrypt_cid(quicly_cid_encryptor_t *self, quicly_cid_plaintext_t *plaintext, const void *encrypted,
                                   size_t len)
{
    return rotating_inner->decrypt_cid(rotating_inner, plaintext, encrypted, len);
}

static int rotating_generate_stateless_reset_token(quicly_cid_encryptor_t *self, void *token, const void *cid)
{
    return rotating_inner->generate_stateless_reset_token(rotating_inner, token, cid);
}

static uint64_t rotating_get_key_generation(quicly_cid_encryptor_t *self)
{
    return rotating_key_generation;
}

static quicly_cid_encryptor_t rotating_encryptor = {rotating_encrypt_cid, rotating_decrypt_cid,
                                                    rotating_generate_stateless_reset_token, rotating_get_key_generation};

static void test_rotate_local_cids_upon_key_change(void)
{
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);

    /* the CIDs are rotated when the server sends packets, and the client switches to the new ones, whose tags start at
     * the next unused tag at the moment the key changes */
    uint64_t first_new_tag = server->next_local_cid_tag;
    ++rotating_key_generation;
    send_and_get_dcid_path_id(server, client);
    exchange_until_idle(client, server);
    ok(send_and_get_dcid_path_id(client, server) >= first_new_tag);

    quicly_free(client);
    quicly_free(server);
}

static void test_rotate_local_cids_after_handshake(void)
{
    quicly_conn_t *client;
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t buf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams = 1;

    /* the key changes while the client has only the CID sent in the first flight */
    ok(quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                      NULL, NULL) == 0);
    ++rotating_key_generation;
    ok(quicly_send(client, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(client->path_spaces[0]->local_cid_set.retire_prior_to == 0);

    quicly_free(client);
}

static void test_rotate_local_cids_multipath(void)
{
    uint64_t saved_max_path_id = quic_ctx.transport_params.initial_max_path_id;
    quic_ctx.transport_params.initial_max_path_id = 1;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    assert(client->path_spaces[1] != NULL && server->path_spaces[1] != NULL);

    /* The unused secondary path has one advertised CID. Its next sequence is independent of the shared CID tag counter. */
    quicly_local_cid_set_t *set = &server->path_spaces[1]->local_cid_set;
    uint64_t next_sequence = set->_next_sequence;
    ok(next_sequence == 1 && server->next_local_cid_tag > next_sequence);
    ++rotating_key_generation;
    send_and_get_dcid_path_id(server, client);
    exchange_until_idle(client, server);

    ok(set->retire_prior_to == next_sequence);
    quicly_remote_cid_set_t *remote = &client->path_spaces[1]->remote_cid_set;
    size_t num_available = 0;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(remote->cids); ++i) {
        if (remote->cids[i].state == QUICLY_REMOTE_CID_UNAVAILABLE)
            continue;
        ok(remote->cids[i].sequence == next_sequence && remote->cids[i].state == QUICLY_REMOTE_CID_AVAILABLE);
        ++num_available;
    }
    ok(num_available == 1);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.initial_max_path_id = saved_max_path_id;
}

static void test_rotate_local_cids(void)
{
    quicly_cid_encryptor_t *orig_encryptor = quic_ctx.cid_encryptor;
    rotating_inner = quicly_new_default_cid_encryptor(&ptls_openssl_aes128ecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                                      ptls_iovec_init("rotate", 6));
    quic_ctx.cid_encryptor = &rotating_encryptor;

    subtest("upon-key-change", test_rotate_local_cids_upon_key_change);
    subtest("after-handshake", test_rotate_local_cids_after_handshake);
    subtest("multipath", test_rotate_local_cids_multipath);

    quic_ctx.cid_encryptor = orig_encryptor;
    quicly_free_default_cid_encryptor(rotating_inner);
}

static void test_cc_limited_drain_and_resume(void)
{
    quicly_init_cc_t *saved_init_cc = quic_ctx.egress[0].cc.init_cc;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_reno_init;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight == 0);

    quicly_stats_t before, stats;
    quicly_get_stats(client, &before);
    uint32_t mtu = client->path_spaces[0]->max_udp_payload_size;
    quicly_address_t dest, src;
    struct iovec datagrams[32];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * mtu], zeros[2 * mtu];
    memset(zeros, 0, sizeof(zeros));
    size_t num_datagrams = 0;

    /* Fill CWND without delivering any packets yet. Each write fits in one packet, leaving no queued data when the window
     * becomes full. Even the early packets, sent with little in flight, should contribute to growth when acknowledged. */
    for (; client->path_spaces[0]->loss.sentmap.bytes_in_flight < before.cc.cwnd && num_datagrams < PTLS_ELEMENTSOF(datagrams);
         ++num_datagrams) {
        ok(quicly_streambuf_egress_write(stream, zeros, mtu - 100 /* leave room for QUIC headers */) == 0);
        size_t count = 1;
        ok(quicly_send(client, &dest, &src, datagrams + num_datagrams, &count, buf + num_datagrams * mtu, mtu) == 0);
        ok(count == 1);
    }
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight >= before.cc.cwnd);
    ok(!scheduler_can_send(client));

    /* Drain the flight one ACK at a time. All of it must count toward slow-start growth, including the tail acknowledged
     * after bytes in flight fall below CWND/2. Do not call the client's send path while draining. */
    for (size_t i = 0; i != num_datagrams; ++i) {
        quicly_decoded_packet_t decoded;
        ok(decode_packets(&decoded, datagrams + i, 1) == 1);
        ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit(server, client) == 1);
        quicly_get_stats(client, &stats);
        uint64_t bytes_acked = stats.num_bytes.ack_received - before.num_bytes.ack_received;
        ok(stats.cc.cwnd == before.cc.cwnd + bytes_acked / mtu * mtu);
    }
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight == 0);
    ok(stats.cc.cwnd > before.cc.cwnd);

    /* Resume with enough data to grow CWND if it were incorrectly still CC-limited, but too little to fill the window. */
    uint32_t cwnd = stats.cc.cwnd;
    ok(quicly_streambuf_egress_write(stream, zeros, 2 * mtu) == 0);
    ok(transmit(client, server) > 0);
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight >= 2 * mtu);
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight < cwnd / 2);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    ok(transmit(server, client) == 1);
    quicly_get_stats(client, &stats);
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight == 0);
    ok(stats.cc.cwnd == cwnd);
    ok(stats.num_packets.lost == 0);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.egress[0].cc.init_cc = saved_init_cc;
}

static void test_setup_send_context(quicly_conn_t *conn, quicly_send_context_t *s, struct iovec *datagram, void *buf,
                                    size_t bufsize)
{
    assert(conn->application != NULL);

    *s = (quicly_send_context_t){
        .current.first_byte = -1,
        .datagrams = datagram,
        .max_datagrams = 1,
        .payload_buf = {.datagram = buf, .end = (uint8_t *)buf + bufsize},
        .send_window = bufsize,
        .dcid = get_dcid(conn, 0 /* path_index */),
    };
    lock_now(conn, 0);
    setup_send_space(conn, QUICLY_EPOCH_1RTT, s);
}

/**
 * An ACK for the packet number to be assigned next acknowledges a packet that has never been sent, hence must be rejected (RFC 9000
 * Section 13.1).
 */
static void test_ack_for_unsent_pn(void)
{
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);

    quicly_ranges_t ranges;
    uint64_t ecn_counts[3] = {0};
    uint8_t ackbuf[64], *ack_end;
    quicly_ranges_init(&ranges);
    ok(quicly_ranges_add(&ranges, server->path_spaces[0]->packet_number, server->path_spaces[0]->packet_number + 1) == 0);
    ok((ack_end = quicly_encode_ack_frame(ackbuf, ackbuf + sizeof(ackbuf), &ranges, ecn_counts, 0)) != NULL);
    quicly_ranges_clear(&ranges);

    struct st_quicly_handle_payload_state_t state = {
        .src = ackbuf + 1 /* skip frame type */, .end = ack_end, .epoch = QUICLY_EPOCH_1RTT, .frame_type = QUICLY_FRAME_TYPE_ACK};
    lock_now(server, 0);
    ok(handle_ack_frame(server, &state) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
    unlock_now(server);

    quicly_free(client);
    quicly_free(server);
}

/* Queues `num_frames` DATAGRAM frames of 1000 bytes each, and returns the number of datagrams the server sends. */
static size_t datagram_frame_amplification_send(quicly_conn_t *server, size_t num_frames)
{
    quicly_address_t dest, src;
    struct iovec datagrams[8];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size], payload[1000] = {0};
    size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);

    for (size_t i = 0; i != num_frames; ++i)
        quicly_send_datagram_frames(server, &(ptls_iovec_t){payload, sizeof(payload)}, 1);
    ok(quicly_send(server, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    return num_datagrams;
}

static size_t num_datagram_frames_received;

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    ++num_datagram_frames_received;
}

static quicly_receive_datagram_frame_t receive_datagram_frame = {on_receive_datagram_frame};

/* DATAGRAM frames are not congestion controlled, but a server that has not validated the client's address stops sending them once
 * the anti-amplification limit is reached. */
static void test_datagram_frame_amplification_limit(void)
{
    quicly_conn_t *client, *server;
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t buf[quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded;
    size_t num_datagrams = 1;

    quic_ctx.transport_params.max_datagram_frame_size = UINT16_MAX;
    quic_ctx.receive_datagram_frame = &receive_datagram_frame;

    /* the client's Initial reaches the server, but nothing the server sends is delivered back, so the address stays unvalidated */
    ok(quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                      NULL, NULL) == 0);
    ok(quicly_send(client, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(decode_packets(&decoded, &datagram, 1) == 1);
    ok(quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL) == 0);
    struct st_quicly_conn_path_t *path = get_path(server, 0);
    uint64_t budget = path->bytes_received * quic_ctx.pre_validation_amplification_limit;

    /* Without the limit, each round would emit another datagram. As is the case with frames subject to the send window, the limit
     * is exceeded by no more than one datagram. */
    for (size_t i = 0; i != 16; ++i)
        num_datagrams = datagram_frame_amplification_send(server, 1);
    ok(num_datagrams == 0);
    ok(path->bytes_sent <= budget + server->path_spaces[0]->max_udp_payload_size);

    /* A datagram is started as long as some allowance remains, but the second frame, which needs another datagram, is not sent (the
     * number of bytes sent is overwritten to set the remaining allowance). */
    uint64_t num_frames_sent = server->super.stats.num_frames_sent.datagram;
    path->bytes_sent = budget - 500;
    ok(datagram_frame_amplification_send(server, 2) == 1);
    ok(server->super.stats.num_frames_sent.datagram == num_frames_sent + 1);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_datagram_frame_size = 0;
    quic_ctx.receive_datagram_frame = NULL;
}

/* DATAGRAM frames larger than the max_datagram_frame_size transport parameter of the peer are not sent, as are all DATAGRAM frames
 * when the peer does not send the transport parameter (RFC 9221 Section 3). */
static void test_datagram_frame_max_size(void)
{
    static uint8_t payload[1000];
    quicly_conn_t *client, *server;

    /* the peer does not support DATAGRAM frames */
    test_setup_connected_peers(&client, &server);
    quicly_send_datagram_frames(server, &(ptls_iovec_t){payload, 1}, 1);
    transmit(server, client);
    ok(server->super.stats.num_frames_sent.datagram == 0);
    quicly_free(client);
    quicly_free(server);

    /* the peer accepts frames up to 1000 bytes, which carry up to 997 bytes of payload (1-byte type and 2-byte length) */
    quic_ctx.transport_params.max_datagram_frame_size = 1000;
    quic_ctx.receive_datagram_frame = &receive_datagram_frame;
    num_datagram_frames_received = 0;
    test_setup_connected_peers(&client, &server);
    quicly_send_datagram_frames(server, &(ptls_iovec_t){payload, 997}, 1);
    transmit(server, client);
    ok(server->super.stats.num_frames_sent.datagram == 1);
    ok(num_datagram_frames_received == 1);
    quicly_send_datagram_frames(server, &(ptls_iovec_t){payload, 998}, 1);
    transmit(server, client);
    ok(server->super.stats.num_frames_sent.datagram == 1);
    ok(num_datagram_frames_received == 1);
    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_datagram_frame_size = 0;
    quic_ctx.receive_datagram_frame = NULL;
}

static quicly_error_t test_handle_stream_level_frame(quicly_conn_t *conn,
                                                     quicly_error_t (*handler)(quicly_conn_t *,
                                                                               struct st_quicly_handle_payload_state_t *),
                                                     const uint8_t *frame, const uint8_t *frame_end)
{
    struct st_quicly_handle_payload_state_t state = {
        .src = frame + 1 /* skip frame type */, .end = frame_end, .epoch = QUICLY_EPOCH_1RTT, .frame_type = *frame};
    lock_now(conn, 0);
    quicly_error_t ret = handler(conn, &state);
    unlock_now(conn);
    return ret;
}

/**
 * Receiving STREAM, STOP_SENDING, or MAX_STREAM_DATA frames for a locally-initiated stream that has not yet been created is a
 * STREAM_STATE_ERROR (RFC 9000 Sections 19.5, 19.8, 19.10).
 */
static void test_frames_for_unopened_local_stream(void)
{
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint8_t buf[32], *end;

    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(server, &stream, 0) == 0);
    ok(stream->stream_id == 1);

    /* STREAM */
    buf[0] = QUICLY_FRAME_TYPE_STREAM_BASE;
    end = quicly_encodev(buf + 1, 1);
    *end++ = 'a';
    ok(test_handle_stream_level_frame(server, handle_stream_frame, buf, end) == 0);
    end = quicly_encodev(buf + 1, 5);
    *end++ = 'a';
    ok(test_handle_stream_level_frame(server, handle_stream_frame, buf, end) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);

    /* STOP_SENDING */
    end = quicly_encode_stop_sending_frame(buf, 1, 0);
    ok(test_handle_stream_level_frame(server, handle_stop_sending_frame, buf, end) == 0);
    end = quicly_encode_stop_sending_frame(buf, 5, 0);
    ok(test_handle_stream_level_frame(server, handle_stop_sending_frame, buf, end) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);
    end = quicly_encode_stop_sending_frame(buf, 3, 0);
    ok(test_handle_stream_level_frame(server, handle_stop_sending_frame, buf, end) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);

    /* MAX_STREAM_DATA */
    end = quicly_encode_max_stream_data_frame(buf, 1, 100000);
    ok(test_handle_stream_level_frame(server, handle_max_stream_data_frame, buf, end) == 0);
    end = quicly_encode_max_stream_data_frame(buf, 5, 100000);
    ok(test_handle_stream_level_frame(server, handle_max_stream_data_frame, buf, end) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);
    end = quicly_encode_max_stream_data_frame(buf, 3, 100000);
    ok(test_handle_stream_level_frame(server, handle_max_stream_data_frame, buf, end) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);

    /* STREAM_DATA_BLOCKED */
    end = quicly_encode_stream_data_blocked_frame(buf, 1, 0);
    ok(test_handle_stream_level_frame(server, handle_stream_data_blocked_frame, buf, end) == 0);
    end = quicly_encode_stream_data_blocked_frame(buf, 5, 0);
    ok(test_handle_stream_level_frame(server, handle_stream_data_blocked_frame, buf, end) == QUICLY_TRANSPORT_ERROR_STREAM_STATE);

    quicly_free(client);
    quicly_free(server);
}

/**
 * MAX_STREAM_DATA and STREAM_DATA_BLOCKED frames create peer-initiated streams, as do other stream-level frames (RFC 9000 Section
 * 3.2).
 */
static void test_frames_opening_peer_stream(void)
{
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint8_t buf[32], *end;

    test_setup_connected_peers(&client, &server);

    end = quicly_encode_max_stream_data_frame(buf, 0, 100 * 1024 * 1024);
    ok(test_handle_stream_level_frame(server, handle_max_stream_data_frame, buf, end) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL && stream->_send_aux.max_stream_data == 100 * 1024 * 1024);

    end = quicly_encode_stream_data_blocked_frame(buf, 4, 0);
    ok(test_handle_stream_level_frame(server, handle_stream_data_blocked_frame, buf, end) == 0);
    ok(quicly_get_stream(server, 4) != NULL);

    quicly_free(client);
    quicly_free(server);
}

static size_t transmit_multipath(quicly_conn_t *src, quicly_conn_t *dst);

static void test_fractional_close_timeout(void)
{
    int64_t saved_now = quic_now;
    for (int draining = 0; draining != 2; ++draining) {
        quic_now = INT64_C(1800000000000);
        quicly_conn_t *client, *server;
        test_setup_connected_peers(&client, &server);

        quic_now_submillisec = 0.75;
        ok(quicly_close(client, 0, "") == 0);
        quicly_address_t dest, src;
        struct iovec datagram;
        uint8_t buf[1500];
        size_t num_datagrams = 1;
        ok(quicly_send(client, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == 0);
        ok(num_datagrams == 1);
        quicly_decoded_packet_t decoded;
        ok(decode_packets(&decoded, &datagram, 1) == 1);
        ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);

        quicly_conn_t *conn = draining ? server : client;
        quicly_stats_t stats;
        quicly_get_stats(conn, &stats);
        int64_t expires_at = ceil(quic_now + quic_now_submillisec +
                                  4 * quicly_rtt_get_pto(&stats.rtt, quicly_get_remote_transport_parameters(conn)->max_ack_delay,
                                                         quic_ctx.egress[0].loss.min_pto));
        ok(quicly_get_first_timeout(conn) == expires_at);

        /* Closing and draining both retain state until the first whole-millisecond tick past the deadline. */
        quic_now_submillisec = 0;
        quic_now = expires_at - 1;
        num_datagrams = 1;
        ok(quicly_send(conn, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == 0);
        ok(quicly_get_first_timeout(conn) == expires_at);
        quic_now = expires_at;
        num_datagrams = 1;
        ok(quicly_send(conn, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == QUICLY_ERROR_FREE_CONNECTION);
        quicly_free(client);
        quicly_free(server);
    }
    quic_now = saved_now;
}

static void test_fractional_rtt_measurement(void)
{
    int64_t saved_now = quic_now;
    quic_now = INT64_C(1800000000000);
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    ok(quicly_get_remote_transport_parameters(client)->ack_delay_exponent == 3);

    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "a", 1) == 0);
    struct iovec datagram;
    uint8_t buf[1500];
    quicly_address_t dest, src;
    size_t num_datagrams = 1;
    quicly_decoded_packet_t decoded;
    quic_now_submillisec = 0.125;
    ok(quicly_send(client, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 1);
    /* The outstanding packet's PTO is still an absolute millisecond deadline. */
    quicly_stats_t stats;
    quicly_get_stats(client, &stats);
    double pto = quicly_rtt_get_pto(&stats.rtt, quicly_get_remote_transport_parameters(client)->max_ack_delay,
                                    quic_ctx.egress[0].loss.min_pto);
    ok(quicly_get_first_timeout(client) == ceil(quic_now + quic_now_submillisec + pto));
    ok(decode_packets(&decoded, &datagram, 1) == 1);
    quic_now_submillisec += 0.625;
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);

    /* Hold the ACK for 1.5ms, then return it over another 625us of propagation delay. Exponent 3 encodes 1.496ms. */
    quic_now += 2;
    quic_now_submillisec = 0.25;
    quicly_send_context_t s;
    test_setup_send_context(server, &s, &datagram, buf, sizeof(buf));
    ok(send_ack(server, &server->application->super, 0, 0, &s) == 0);
    ok(commit_send_packet(server, &s, 0) == 0);
    unlock_now(server);
    ok(decode_packets(&decoded, &datagram, 1) == 1);
    quic_now_submillisec += 0.625;
    ok(quicly_receive(client, NULL, &fake_address.sa, &decoded) == 0);

    /* Observe the public statistics, exercising the clock, sentmap, ACK encoding and RTT update together. */
    quicly_get_stats(client, &stats);
    ok(fabsf(stats.rtt.latest - 1.254f) < 0.000001f);

    /* Closing retains the fractional PTO derived from that measurement. */
    pto = quicly_rtt_get_pto(&stats.rtt, quicly_get_remote_transport_parameters(client)->max_ack_delay,
                             quic_ctx.egress[0].loss.min_pto);
    ok(pto != floor(pto));
    ok(quicly_close(client, 0, "") == 0);
    num_datagrams = 1;
    ok(quicly_send(client, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 1);
    ok(quicly_get_first_timeout(client) == ceil(quic_now + quic_now_submillisec + 4 * pto));

    quicly_free(client);
    quicly_free(server);
    quic_now_submillisec = 0;
    quic_now = saved_now;
}

static void test_time_threshold_loss_episode(void)
{
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    quicly_address_t dest, src;
    struct iovec datagrams[10];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size], data[4000] = {0};
    quicly_decoded_packet_t decoded;
    size_t num_datagrams;
    quicly_stats_t stats;

    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(client, &stream, 0) == 0);

    /* send two packets; drop the first and deliver the second */
    ok(quicly_streambuf_egress_write(stream, data, 2000) == 0);
    num_datagrams = 2;
    ok(quicly_send(client, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 2);
    ok(decode_packets(&decoded, datagrams + 1, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    ok(transmit(server, client) == 1);

    /* upon the alarm, the first packet is declared lost by time threshold; drop the first packet being sent, deliver the rest */
    quic_now = quicly_get_first_timeout(client);
    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    quicly_get_stats(client, &stats);
    ok(stats.num_packets.lost_time_threshold == 1);
    ok(stats.cc.num_loss_episodes == 1);
    for (size_t i = 1; i < num_datagrams; ++i) {
        ok(decode_packets(&decoded, datagrams + i, 1) == 1);
        ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    }

    /* deliver packets sent subsequently, so that the dropped packet is declared lost */
    ok(quicly_streambuf_egress_write(stream, data, 4000) == 0);
    ok(transmit(client, server) > 0);
    ok(transmit(server, client) == 1);
    quicly_get_stats(client, &stats);
    ok(stats.num_packets.lost == 2);

    /* loss of the packet sent upon the alarm belongs to the same congestion episode */
    ok(stats.cc.num_loss_episodes == 1);

    quicly_free(client);
    quicly_free(server);
}

static void test_time_threshold_loss_in_recovery(void)
{
    uint32_t initcwnd_packets_backup = quic_ctx.egress[0].cc.initcwnd_packets;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    quicly_address_t dest, src;
    struct iovec first[2], second[18], datagrams[10];
    uint8_t first_buf[PTLS_ELEMENTSOF(first) * quic_ctx.transport_params.max_udp_payload_size],
        second_buf[PTLS_ELEMENTSOF(second) * quic_ctx.transport_params.max_udp_payload_size],
        buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size], data[40000] = {0};
    quicly_decoded_packet_t decoded;
    size_t num_datagrams;
    quicly_stats_t stats;

    quic_ctx.egress[0].cc.initcwnd_packets = 20;
    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);

    /* send P0 and P1, then P2 to P19 5ms later; deliver P1 with an RTT of 10ms */
    num_datagrams = PTLS_ELEMENTSOF(first);
    ok(quicly_send(client, &dest, &src, first, &num_datagrams, first_buf, sizeof(first_buf)) == 0);
    ok(num_datagrams == PTLS_ELEMENTSOF(first));
    quic_now += 5;
    num_datagrams = PTLS_ELEMENTSOF(second);
    ok(quicly_send(client, &dest, &src, second, &num_datagrams, second_buf, sizeof(second_buf)) == 0);
    ok(num_datagrams == PTLS_ELEMENTSOF(second));
    quic_now += 5;
    ok(decode_packets(&decoded, first + 1, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    ok(transmit(server, client) == 1);

    /* upon the alarm, P0 is declared lost by time threshold, entering recovery; packets being sent are kept in flight */
    quic_now = client->path_spaces[0]->loss.alarm_at;
    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    quicly_get_stats(client, &stats);
    ok(stats.num_packets.lost_time_threshold == 1);

    /* deliver P3, so that P2 becomes subject to time-threshold loss detection while in recovery with bytes in flight exceeding CWND
     * by one packet or more */
    quic_now += 3;
    ok(decode_packets(&decoded, second + 1, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    ok(transmit(server, client) == 1);
    ok(client->path_spaces[0]->loss.loss_time != INT64_MAX);
    ok(client->path_spaces[0]->loss.largest_acked_packet_plus1.all_ - 1 < client->path_spaces[0]->cc.recovery_end);
    ok(client->path_spaces[0]->loss.sentmap.bytes_in_flight >=
       client->path_spaces[0]->cc.cwnd + client->path_spaces[0]->max_udp_payload_size);

    /* the alarm is not scheduled for time-threshold loss detection */
    ok(client->path_spaces[0]->loss.alarm_at != client->path_spaces[0]->loss.loss_time);

    /* P2 is declared lost upon receiving the next ACK, that is sent in response to P4 and P5 */
    quic_now = client->path_spaces[0]->loss.loss_time;
    for (size_t i = 2; i <= 3; ++i) {
        ok(decode_packets(&decoded, second + i, 1) == 1);
        ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    }
    ok(transmit(server, client) == 1);
    quicly_get_stats(client, &stats);
    ok(stats.num_packets.lost == 2);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.egress[0].cc.initcwnd_packets = initcwnd_packets_backup;
}

static void retransmit_trigger_reset_stream(quicly_conn_t *client, quicly_conn_t *server)
{
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 1) == 0);
    quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1));
}

static void retransmit_trigger_stop_sending(quicly_conn_t *client, quicly_conn_t *server)
{
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    quicly_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1));
}

/* client sends 3/4 of the stream- and connection-level window; the server consumes it, which opens both windows */
static void retransmit_trigger_max_data(quicly_conn_t *client, quicly_conn_t *server)
{
    static uint8_t buf[3072];
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    quicly_streambuf_egress_write(stream, buf, sizeof(buf));
    transmit(client, server);
    quicly_stream_t *server_stream = quicly_get_stream(server, stream->stream_id);
    ok(server_stream != NULL);
    quicly_streambuf_ingress_shift(server_stream, ((quicly_streambuf_t *)server_stream->data)->ingress.off);
}

/* client writes more than the windows permit */
static void retransmit_trigger_data_blocked(quicly_conn_t *client, quicly_conn_t *server)
{
    static uint8_t buf[8192];
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    quicly_streambuf_egress_write(stream, buf, sizeof(buf));
}

/* client finishes a uni stream; once the server retires it, stream credit is returned */
static void retransmit_trigger_max_streams_uni(quicly_conn_t *client, quicly_conn_t *server)
{
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 1) == 0);
    quicly_stream_id_t stream_id = stream->stream_id;
    quicly_streambuf_egress_write(stream, "a", 1);
    quicly_streambuf_egress_shutdown(stream);
    transmit(client, server);
    ok(quicly_get_stream(server, stream_id) == NULL);
}

/* client and server finish both directions of a bidi stream; once the server retires it, stream credit is returned */
static void retransmit_trigger_max_streams_bidi(quicly_conn_t *client, quicly_conn_t *server)
{
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    quicly_stream_id_t stream_id = stream->stream_id;
    quicly_streambuf_egress_write(stream, "a", 1);
    quicly_streambuf_egress_shutdown(stream);
    transmit(client, server);
    quicly_stream_t *server_stream = quicly_get_stream(server, stream_id);
    ok(server_stream != NULL);
    quicly_streambuf_egress_shutdown(server_stream);
    transmit(server, client);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    ok(quicly_get_stream(server, stream_id) == NULL);
}

/* client opens one more uni stream than permitted */
static void retransmit_trigger_streams_blocked(quicly_conn_t *client, quicly_conn_t *server)
{
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 1) == 0);
    ok(quicly_open_stream(client, &stream, 1) == 0);
}

/* same as above, but after a STREAMS_BLOCKED frame has been acked and the peer has raised the limit */
static void retransmit_trigger_streams_blocked_raised(quicly_conn_t *client, quicly_conn_t *server)
{
    quicly_stream_t *stream, *blocked;
    /* get blocked at the initial limit, and have the STREAMS_BLOCKED frame acked */
    ok(quicly_open_stream(client, &stream, 1) == 0);
    ok(quicly_open_stream(client, &blocked, 1) == 0);
    transmit(client, server);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    /* close the first stream so that the server raises the limit, which opens the blocked stream */
    quicly_streambuf_egress_write(stream, "a", 1);
    quicly_streambuf_egress_shutdown(stream);
    transmit(client, server);
    transmit(server, client);
    /* get blocked again */
    ok(quicly_open_stream(client, &stream, 1) == 0);
}

static void retransmit_trigger_new_token(quicly_conn_t *client, quicly_conn_t *server)
{
    ok(quicly_send_resumption_token(server) == 0);
}

static quicly_error_t retransmit_generate_resumption_token(quicly_generate_resumption_token_t *self, quicly_conn_t *conn,
                                                           ptls_buffer_t *buf, quicly_address_token_plaintext_t *token)
{
    return ptls_buffer_reserve(buf, 16) == 0 ? (buf->off += 16, 0) : PTLS_ERROR_NO_MEMORY;
}

/**
 * Tests that a frame is resent when the packet carrying it is lost. After `trigger` is run, the two endpoints exchange packets.
 * The datagrams of the first flight carrying the frame are dropped, and the frame is expected to be sent again before the sender
 * declares a packet lost, or at the latest by the second PTO.
 */
static void do_test_retransmit(size_t frame_off, int from_server, void (*trigger)(quicly_conn_t *client, quicly_conn_t *server))
{
#define FRAME_COUNT(stats) (*(uint64_t *)((char *)&(stats) + frame_off))
    quicly_conn_t *client, *server, *sender, *receiver;
    quicly_stats_t at_drop;
    int64_t dropped_at = 0;
    int dropped = 0;

    test_setup_connected_peers(&client, &server);
    sender = from_server ? server : client;
    receiver = from_server ? client : server;
    trigger(client, server);

    for (size_t i = 0; i < 100; ++i) {
        int64_t sender_at = quicly_get_first_timeout(sender), receiver_at = quicly_get_first_timeout(receiver),
                next_at = sender_at < receiver_at ? sender_at : receiver_at;
        /* if nothing other than the idle timeout is scheduled, the frame is never going to be resent */
        if (dropped && next_at > dropped_at + 10000)
            break;
        if (quic_now < next_at)
            quic_now = next_at;
        if (receiver_at < sender_at) {
            transmit(receiver, sender);
            continue;
        }
        /* send datagrams, dropping them if they are the first to carry the frame */
        quicly_address_t dest, src;
        struct iovec datagrams[10];
        uint8_t buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
        size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
        quicly_stats_t before, after;
        quicly_get_stats(sender, &before);
        ok(quicly_send(sender, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
        quicly_get_stats(sender, &after);
        if (!dropped) {
            if (FRAME_COUNT(after) != FRAME_COUNT(before)) {
                at_drop = after;
                dropped_at = quic_now;
                dropped = 1;
                continue;
            }
        } else {
            if (FRAME_COUNT(after) != FRAME_COUNT(at_drop))
                goto Exit;
            if (after.num_packets.lost != at_drop.num_packets.lost || after.num_ptos > at_drop.num_ptos + 2)
                break;
        }
        for (size_t j = 0; j != num_datagrams; ++j) {
            quicly_decoded_packet_t decoded[4];
            size_t num_decoded = decode_packets(decoded, datagrams + j, 1);
            for (size_t k = 0; k != num_decoded; ++k) {
                quicly_error_t ret = quicly_receive(receiver, NULL, &fake_address.sa, decoded + k);
                ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
            }
        }
    }
    ok(!"frame was not retransmitted");

Exit:
    quicly_free(client);
    quicly_free(server);
#undef FRAME_COUNT
}

static void test_retransmit(void)
{
    static quicly_generate_resumption_token_t generate_resumption_token = {retransmit_generate_resumption_token};
    quicly_transport_parameters_t orig = quic_ctx.transport_params;
    quic_ctx.generate_resumption_token = &generate_resumption_token;
    quic_ctx.transport_params.max_streams_bidi = 1;
    quic_ctx.transport_params.max_streams_uni = 1;
    quic_ctx.transport_params.max_data = 4096;
    quic_ctx.transport_params.max_stream_data.bidi_local = 4096;
    quic_ctx.transport_params.max_stream_data.bidi_remote = 4096;
    quic_ctx.transport_params.max_stream_data.uni = 4096;

#define TEST(frame, from_server, trigger)                                                                                          \
    subtest(#frame, do_test_retransmit, offsetof(quicly_stats_t, num_frames_sent.frame), from_server, retransmit_trigger_##trigger)
    TEST(reset_stream, 0, reset_stream);
    TEST(stop_sending, 0, stop_sending);
    TEST(max_stream_data, 1, max_data);
    TEST(max_data, 1, max_data);
    TEST(stream_data_blocked, 0, data_blocked);
    TEST(data_blocked, 0, data_blocked);
    TEST(max_streams_bidi, 1, max_streams_bidi);
    TEST(max_streams_uni, 1, max_streams_uni);
    TEST(streams_blocked, 0, streams_blocked);
    TEST(streams_blocked, 0, streams_blocked_raised);
    TEST(new_token, 1, new_token);
#undef TEST

    quic_ctx.transport_params = orig;
    quic_ctx.generate_resumption_token = NULL;
}

/**
 * Tests that requesting a resumption token is a no-op when the context has no `generate_resumption_token` callback.
 */
static void test_send_resumption_token_without_generator(void)
{
    quicly_conn_t *client, *server;
    quicly_stats_t stats;

    ok(quic_ctx.generate_resumption_token == NULL);
    test_setup_connected_peers(&client, &server);

    ok(quicly_send_resumption_token(server) == 0);
    exchange_until_idle(client, server);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);
    quicly_get_stats(server, &stats);
    ok(stats.num_frames_sent.new_token == 0);

    quicly_free(client);
    quicly_free(server);
}

static void test_retransmit_max_stream_data_lower_window(void)
{
    uint64_t max_stream_data_orig = quic_ctx.transport_params.max_stream_data.bidi_remote;
    quic_ctx.transport_params.max_stream_data.bidi_remote = 4096;

    quicly_conn_t *client, *server;
    quicly_stream_t *client_stream, *server_stream;
    static uint8_t data[3072];

    test_setup_connected_peers(&client, &server);

    /* consuming 3072 bytes raises the advertised limit from 4096 to 7168 */
    ok(quicly_open_stream(client, &client_stream, 0) == 0);
    ok(quicly_streambuf_egress_write(client_stream, data, sizeof(data)) == 0);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    ok(((quicly_streambuf_t *)server_stream->data)->ingress.off == sizeof(data));
    quicly_streambuf_ingress_shift(server_stream, sizeof(data));

    /* send the MAX_STREAM_DATA update, dropping the datagrams */
    quicly_address_t dest, src;
    struct iovec datagrams[10];
    uint8_t packetsbuf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(server, &dest, &src, datagrams, &num_datagrams, packetsbuf, sizeof(packetsbuf)) == 0);
    ok(num_datagrams > 0);
    ok(server->super.stats.num_frames_sent.max_stream_data == 1);
    ok(server_stream->_send_aux.max_stream_data_sender.committed == 7168);
    ok(client_stream->_send_aux.max_stream_data == 4096);

    /* lower the window before PTO; retransmission must preserve the already advertised limit */
    quicly_stream_set_receive_window(server_stream, 1024);
    quic_now = quicly_get_first_timeout(server);
    ok(transmit(server, client) > 0);
    ok(server->super.stats.num_frames_sent.max_stream_data == 2);
    ok(server_stream->_send_aux.max_stream_data_sender.committed == 7168);
    ok(client_stream->_send_aux.max_stream_data == 7168);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_stream_data.bidi_remote = max_stream_data_orig;
}

static void test_stream_credit_growth(void)
{
    uint64_t orig = quic_ctx.transport_params.max_streams_uni;
    quic_ctx.transport_params.max_streams_uni = 32;
    quicly_conn_t *client, *server;
    quicly_stream_t *streams[32];
    static const size_t updates[] = {1, 2, 4, 8, 16, 24};
    size_t next_update = 0;
    uint64_t limit = 32;

    test_setup_connected_peers(&client, &server);
    for (size_t i = 0; i < PTLS_ELEMENTSOF(streams); ++i) {
        ok(quicly_open_stream(client, streams + i, 1) == 0);
        ok(quicly_streambuf_egress_write(streams[i], "a", 1) == 0);
    }
    exchange_until_idle(client, server);
    ok(server->super.remote.uni.num_streams == 32);
    ok(server->super.stats.num_frames_sent.max_streams_uni == 0);

    /* Keep the other streams open: credit must return without STREAMS_BLOCKED, first exponentially, then every 8 closures. */
    for (size_t closed = 1; closed <= 24; ++closed) {
        quicly_streambuf_egress_shutdown(streams[closed - 1]);
        exchange_until_idle(client, server);
        if (closed == updates[next_update]) {
            limit = 32 + closed;
            ++next_update;
        }
        ok(client->egress.max_streams.uni.count == limit);
        ok(server->super.stats.num_frames_sent.max_streams_uni == next_update);
    }
    ok(client->super.stats.num_frames_sent.streams_blocked == 0);
    quicly_free(client);
    quicly_free(server);

    /* Free room first, then consume the remaining advertised IDs. Opening streams must schedule the credit update too. */
    quic_ctx.transport_params.max_streams_uni = 10;
    test_setup_connected_peers(&client, &server);
    for (size_t i = 0; i < 8; ++i) {
        ok(quicly_open_stream(client, streams + i, 1) == 0);
        ok(quicly_streambuf_egress_write(streams[i], "a", 1) == 0);
    }
    exchange_until_idle(client, server);
    quicly_streambuf_egress_shutdown(streams[0]);
    exchange_until_idle(client, server);
    ok(client->egress.max_streams.uni.count == 10);
    for (size_t i = 8; i < 10; ++i) {
        ok(quicly_open_stream(client, streams + i, 1) == 0);
        ok(quicly_streambuf_egress_write(streams[i], "a", 1) == 0);
    }
    exchange_until_idle(client, server);
    ok(client->egress.max_streams.uni.count == 11);
    ok(client->super.stats.num_frames_sent.streams_blocked == 0);
    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_streams_uni = orig;
}

static void test_data_credit_growth(void)
{
    quicly_transport_parameters_t orig = quic_ctx.transport_params;
    quic_ctx.transport_params.max_data = quic_ctx.transport_params.max_stream_data.bidi_remote = 4096;
    quicly_conn_t *client, *server;
    quicly_stream_t *client_stream, *server_stream;
    static const uint8_t data[4096] = {0};
    static const size_t updates[] = {1, 2, 4, 8, 16};
    size_t next_update = 1;
    uint64_t limit = 4097;

    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(client, &client_stream, 0) == 0);
    ok(quicly_streambuf_egress_write(client_stream, data, sizeof(data) - 2) == 0);
    exchange_until_idle(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    /* Free one byte while credit remains, then receive the last two bytes. Receiving must schedule both credit updates. */
    quicly_streambuf_ingress_shift(server_stream, 1);
    exchange_until_idle(client, server);
    ok(client_stream->_send_aux.max_stream_data == 4096);
    ok(client->egress.max_data.permitted == 4096);
    /* Model a peer that omits the optional DATA_BLOCKED signal, so only observed consumption can trigger an update. */
    client->egress.data_blocked = QUICLY_SENDER_STATE_ACKED;
    ok(quicly_streambuf_egress_write(client_stream, data, 2) == 0);
    exchange_until_idle(client, server);
    ok(server->ingress.max_data.bytes_consumed == 4096);
    ok(client_stream->_send_aux.max_stream_data == 4097);
    ok(client->egress.max_data.permitted == 4097);
    for (size_t released = 2; released <= 16; ++released) {
        quicly_streambuf_ingress_shift(server_stream, 1);
        exchange_until_idle(client, server);
        if (released == updates[next_update]) {
            limit = 4096 + released;
            ++next_update;
        }
        ok(client_stream->_send_aux.max_stream_data == limit);
        ok(client->egress.max_data.permitted == limit);
    }

    /* Exhaust the newly granted credit, then release one byte: both limits must advance immediately again. */
    client->egress.data_blocked = QUICLY_SENDER_STATE_ACKED;
    ok(quicly_streambuf_egress_write(client_stream, data, 16) == 0);
    exchange_until_idle(client, server);
    quicly_streambuf_ingress_shift(server_stream, 1);
    exchange_until_idle(client, server);
    ok(client_stream->_send_aux.max_stream_data == 4113);
    ok(client->egress.max_data.permitted == 4113);
    ok(client->super.stats.num_frames_sent.data_blocked == 0);
    ok(client->super.stats.num_frames_sent.stream_data_blocked == 0);
    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params = orig;
}

static void test_destroy_returns_credit_fin(void)
{
    uint64_t max_streams_uni_orig = quic_ctx.transport_params.max_streams_uni;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint64_t consumed, shifted;
    quicly_error_t ret;

    quic_ctx.transport_params.max_streams_uni = 1;
    test_setup_connected_peers(&client, &server);

    /* the client sends five bytes and closes the stream */
    ret = quicly_open_stream(client, &stream, 1);
    ok(ret == 0);
    quicly_streambuf_egress_write(stream, "hello", 5);
    ok(quicly_streambuf_egress_shutdown(stream) == 0);
    transmit(client, server);

    /* being unidirectional, the stream is destroyed as soon as it is received in full, the application never having read it */
    ok(quicly_get_stream(server, stream->stream_id) == NULL);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 5);
    ok(shifted == 5);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_streams_uni = max_streams_uni_orig;
}

static void test_destroy_returns_credit_reset(void)
{
    uint64_t max_streams_uni_orig = quic_ctx.transport_params.max_streams_uni;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint64_t consumed, shifted;
    quicly_error_t ret;

    quic_ctx.transport_params.max_streams_uni = 1;
    test_setup_connected_peers(&client, &server);

    /* the client sends five bytes, then resets the stream */
    ret = quicly_open_stream(client, &stream, 1);
    ok(ret == 0);
    quicly_streambuf_egress_write(stream, "hello", 5);
    transmit(client, server);
    quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(123));
    transmit(client, server);

    ok(quicly_get_stream(server, stream->stream_id) == NULL);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 5);
    ok(shifted == 5);

    quicly_free(client);
    quicly_free(server);

    /* when the reset arrives before the bytes it accounts for, the credit of those bytes is returned at once; they are never
     * received, no memory ever being allocated to hold them */
    test_setup_connected_peers(&client, &server);
    ret = quicly_open_stream(client, &stream, 1);
    ok(ret == 0);
    quicly_streambuf_egress_write(stream, "hello", 5);
    {
        /* the datagram carrying the five bytes is dropped, the reset that follows nonetheless reporting them as the final size */
        quicly_address_t dest, src;
        struct iovec datagram;
        uint8_t buf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_datagrams = 1;
        ret = quicly_send(client, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf));
        ok(ret == 0);
        ok(num_datagrams == 1);
    }
    quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(123));
    transmit(client, server);
    ok(quicly_get_stream(server, stream->stream_id) == NULL);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 5);
    ok(shifted == 5);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_streams_uni = max_streams_uni_orig;
}

static quicly_error_t refuse_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    return QUICLY_ERROR_STATE_EXHAUSTION;
}

static void test_stream_open_refused(void)
{
    uint64_t max_streams_uni_orig = quic_ctx.transport_params.max_streams_uni;
    quicly_stream_open_t *stream_open_orig = quic_ctx.stream_open, refuse = {refuse_stream_open};
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[4];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * 1500];
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 2];
    size_t num_datagrams = PTLS_ELEMENTSOF(datagrams), num_packets, i;
    quicly_error_t ret, last_ret = 0;

    quic_ctx.transport_params.max_streams_uni = 1;
    test_setup_connected_peers(&client, &server);

    /* the client opens a stream, which the server refuses */
    ret = quicly_open_stream(client, &stream, 1);
    ok(ret == 0);
    quicly_streambuf_egress_write(stream, "hello", 5);
    quic_ctx.stream_open = &refuse;
    ret = quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    num_packets = decode_packets(decoded, datagrams, num_datagrams);
    for (i = 0; i != num_packets; ++i) {
        if ((ret = quicly_receive(server, NULL, &fake_address.sa, decoded + i)) != 0)
            last_ret = ret;
    }
    ok(last_ret == QUICLY_ERROR_STATE_EXHAUSTION);
    quic_ctx.stream_open = stream_open_orig;

    /* the refusal being fatal, the server closes the connection; freeing it destroys the stream that was refused */
    ok(quicly_close(server, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "") == 0);
    quicly_free(server);
    quicly_free(client);
    quic_ctx.transport_params.max_streams_uni = max_streams_uni_orig;
}

/**
 * This test checks that lowering the receive window does not cause the data within the limit already advertised to be rejected,
 * while the data exceeding that limit is.
 */
static void test_lower_receive_window(void)
{
    uint64_t max_stream_data_orig = quic_ctx.transport_params.max_stream_data.bidi_local;
    quic_ctx.transport_params.max_stream_data.bidi_local = 4096;

    quicly_conn_t *client, *server;
    quicly_stream_t *client_stream, *server_stream;
    static uint8_t buf[4096];

    test_setup_connected_peers(&client, &server);

    /* open a stream, advertising a limit of 4096 bytes to the server */
    ok(quicly_open_stream(client, &client_stream, 0) == 0);
    quicly_streambuf_egress_write(client_stream, "a", 1);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);

    /* lower the receive window after the limit has been advertised */
    quicly_stream_set_receive_window(client_stream, sizeof(buf) / 2);

    /* the server sends up to the advertised limit, which is accepted */
    quicly_streambuf_egress_write(server_stream, buf, sizeof(buf));
    transmit(server, client);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(((quicly_streambuf_t *)client_stream->data)->ingress.off == sizeof(buf));

    /* make the server send one more byte, which exceeds the advertised limit */
    server_stream->_send_aux.max_stream_data = sizeof(buf) + 1;
    quicly_streambuf_egress_write(server_stream, "a", 1);
    transmit(server, client);
    ok(quicly_get_state(client) >= QUICLY_STATE_CLOSING &&
       quicly_get_close_reason(client, NULL, NULL, NULL) == QUICLY_TRANSPORT_ERROR_FLOW_CONTROL);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_stream_data.bidi_local = max_stream_data_orig;
}

/**
 * Feeds hand-crafted frames to `conn`, so that the frame sequences that quicly's own sender does not produce can be exercised.
 */
static quicly_error_t inject_frames(quicly_conn_t *conn, const void *frames, size_t len)
{
    uint64_t offending_frame_type;
    int is_ack_only, is_probe_only;
    quicly_error_t ret;

    lock_now(conn, 0);
    ret = handle_payload(conn, QUICLY_EPOCH_1RTT, 0, NULL, frames, len, &offending_frame_type, &is_ack_only, &is_probe_only);
    unlock_now(conn);

    return ret;
}

/**
 * The Reliable Size can be below what the peer has already sent; quicly's own sender never does that, raising the value to
 * `size_inflight`. Checks that the final size is charged to connection-level flow control exactly once, even though the bytes
 * above the Reliable Size have already been received.
 */
/**
 * Two RESET_STREAMs, each with a final size that fits the stream-level window but which together overrun the connection-level
 * limit. Mirrors the `reset-stream-overflow-connection` case of t/e2e.t, deterministically.
 */
static void test_reset_stream_overflow_connection(void)
{
    /* RESET_STREAM(id=0, error=0, final=1000), RESET_STREAM(id=4, error=0, final=1000) */
    static const uint8_t reset0[] = {0x04, 0x00, 0x00, 0x43, 0xe8};
    static const uint8_t reset4[] = {0x04, 0x04, 0x00, 0x43, 0xe8};
    quicly_max_stream_data_t max_stream_data_orig = quic_ctx.transport_params.max_stream_data;
    uint64_t max_data_orig = quic_ctx.transport_params.max_data;
    quicly_conn_t *client, *server;

    quic_ctx.transport_params.max_stream_data = (quicly_max_stream_data_t){1000, 1000, 1000};
    quic_ctx.transport_params.max_data = 1500;
    test_setup_connected_peers(&client, &server);

    /* the first fits both limits */
    ok(inject_frames(server, reset0, sizeof(reset0)) == 0);

    /* the second fits the stream-level window, but the two together exceed the connection-level limit */
    ok(inject_frames(server, reset4, sizeof(reset4)) == QUICLY_TRANSPORT_ERROR_FLOW_CONTROL);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.max_stream_data = max_stream_data_orig;
    quic_ctx.transport_params.max_data = max_data_orig;
}

static void test_reset_stream_at_accounting(void)
{
    /* STREAM(id=0, off=5, len=5) "56789", then RESET_STREAM_AT(id=0, error=11, final_size=10, reliable_size=3) */
    static const uint8_t data_above[] = {0x0e, 0x00, 0x05, 0x05, '5', '6', '7', '8', '9'};
    static const uint8_t reset[] = {0x24, 0x00, 0x0b, 0x0a, 0x03};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint64_t consumed;

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    /* the offsets received up to are charged, the bytes below them being still missing */
    ok(inject_frames(server, data_above, sizeof(data_above)) == 0);
    quicly_get_max_data(server, NULL, NULL, &consumed, NULL);
    ok(consumed == 10);

    /* the peer commits to the first 3 bytes only, although it has sent 10 */
    ok(inject_frames(server, reset, sizeof(reset)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    ok(stream->recvstate.app_error_code == 11);

    /* the final size is charged once; the bytes above the Reliable Size that had already arrived are not charged again */
    quicly_get_max_data(server, NULL, NULL, &consumed, NULL);
    ok(consumed == 10);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

/**
 * Credit is returned by a subsequent reset only when it lowers the offset up to which memory is allocated. Bytes stranded above the
 * Reliable Size keep that offset in place, hence neither a repeated reset nor one reducing the Reliable Size returns anything.
 */
static void test_reset_stream_at_repeated(int with_data_above)
{
    /* STREAM(id=0, off=7, len=3) "789", RESET_STREAM_AT(id=0, error=11, final=10, reliable=5 or 3), STREAM(id=0, len=3) "012" */
    static const uint8_t data_above[] = {0x0e, 0x00, 0x07, 0x03, '7', '8', '9'};
    static const uint8_t reset5[] = {0x24, 0x00, 0x0b, 0x0a, 0x05};
    static const uint8_t reset3[] = {0x24, 0x00, 0x0b, 0x0a, 0x03};
    static const uint8_t prefix[] = {0x0a, 0x00, 0x03, '0', '1', '2'};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint64_t consumed, shifted;

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    if (with_data_above)
        ok(inject_frames(server, data_above, sizeof(data_above)) == 0);

    /* the first reset returns the credit above the offset of allocation, which is 10 when bytes are stranded above, 5 otherwise */
    ok(inject_frames(server, reset5, sizeof(reset5)) == 0);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 10);
    ok(shifted == (with_data_above ? 0 : 5));

    /* a repeated reset changes nothing */
    ok(inject_frames(server, reset5, sizeof(reset5)) == 0);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 10);
    ok(shifted == (with_data_above ? 0 : 5));

    /* reducing the Reliable Size returns the credit of the bytes that the peer is no longer committed to, unless memory remains
     * allocated for the bytes stranded above */
    ok(inject_frames(server, reset3, sizeof(reset3)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    ok(stream->recvstate.eos == 3);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 10);
    ok(shifted == (with_data_above ? 0 : 7));

    /* once the committed prefix is received and consumed, the credit returned adds up to the final size, unless memory is held for
     * the bytes stranded above, in which case the rest is returned when the stream is destroyed */
    ok(inject_frames(server, prefix, sizeof(prefix)) == 0);
    ok(quicly_recvstate_transfer_complete(&stream->recvstate));
    quicly_streambuf_ingress_shift(stream, 3);
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 10);
    ok(shifted == (with_data_above ? 3 : 10));

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

/**
 * Section 5.2 forbids changing the application error code, and requires a Reliable Size that does not reduce the commitment to be
 * ignored. Those are separate rules: a first reset whose Reliable Size equals the Final Size reduces nothing, yet its error code
 * has to be retained and surfaced once the remaining bytes arrive.
 */
static void test_reset_stream_at_gap_after_reset(void)
{
    /* RESET_STREAM_AT(id=0, error=11, final=10, reliable=5), STREAM(id=0, off=7, len=3), STREAM(id=0, len=5) */
    static const uint8_t reset[] = {0x24, 0x00, 0x0b, 0x0a, 0x05};
    static const uint8_t tail[] = {0x0e, 0x00, 0x07, 0x03, '7', '8', '9'};
    static const uint8_t prefix[] = {0x0a, 0x00, 0x05, '0', '1', '2', '3', '4'};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    test_streambuf_t *streambuf;

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    /* the peer commits to the first five bytes of a stream that ends at ten */
    ok(inject_frames(server, reset, sizeof(reset)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    streambuf = stream->data;
    ok(stream->recvstate.eos == 5);

    /* bytes above the reliable size arrive; they are dropped rather than buffered, the peer no longer being committed to the gap
     * below them and the credit of everything above the reliable size having been returned when the reset was received */
    ok(inject_frames(server, tail, sizeof(tail)) == 0);
    ok(!quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(stream->recvstate.received.num_ranges == 1);

    /* completing the committed prefix completes the transfer regardless; waiting for the gap would hang the stream */
    ok(inject_frames(server, prefix, sizeof(prefix)) == 0);
    ok(quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(streambuf->error_received.reset_on_receive == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(11));
    ok(quicly_recvstate_bytes_available(&stream->recvstate) == 5);
    ok(quicly_streambuf_ingress_get(stream).len == 5);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

static void test_reset_stream_at_data_above(void)
{
    /* RESET_STREAM_AT(id=0, error=11, final=10, reliable=5), then STREAM(id=0, len=10) "0123456789" */
    static const uint8_t reset[] = {0x24, 0x00, 0x0b, 0x0a, 0x05};
    static const uint8_t whole[] = {0x0a, 0x00, 0x0a, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    test_streambuf_t *streambuf;
    uint64_t consumed, shifted;

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    /* the peer commits to the first 5 bytes of a stream that ends at 10 */
    ok(inject_frames(server, reset, sizeof(reset)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    streambuf = stream->data;
    ok(stream->recvstate.eos == 5);
    ok(!quicly_recvstate_transfer_complete(&stream->recvstate));

    /* the final size is charged, and the credit of the 5 bytes above the Reliable Size returned at once; that of the 5 below is
     * not, the peer being committed to sending them and the receive buffer therefore still to allocate for them */
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 10);
    ok(shifted == 5);

    /* All 10 bytes then arrive in one frame. Only the 5 committed to are kept; the rest is dropped, the peer having been given
     * back the credit for it when it reset. */
    ok(inject_frames(server, whole, sizeof(whole)) == 0);
    ok(quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(stream->recvstate.eos == 5);
    ok(quicly_recvstate_bytes_available(&stream->recvstate) == 5);
    ok(quicly_streambuf_ingress_get(stream).len == 5);
    ok(buffer_is(&streambuf->super.ingress, "01234"));
    ok(streambuf->error_received.reset_on_receive == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(11));

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

static void test_reset_stream_at_gap_above(void)
{
    /* STREAM(id=0, off=7, len=3) "789", RESET_STREAM_AT(id=0, error=11, final=10, reliable=5), STREAM(id=0, len=5) "01234" */
    static const uint8_t data_above[] = {0x0e, 0x00, 0x07, 0x03, '7', '8', '9'};
    static const uint8_t reset[] = {0x24, 0x00, 0x0b, 0x0a, 0x05};
    static const uint8_t prefix[] = {0x0a, 0x00, 0x05, '0', '1', '2', '3', '4'};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint64_t consumed, shifted;

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    /* bytes above the Reliable Size land in the receive buffer before the reset is known, leaving [5,7) missing */
    ok(inject_frames(server, data_above, sizeof(data_above)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    ok(inject_frames(server, reset, sizeof(reset)) == 0);
    ok(stream->recvstate.eos == 5);

    /* the reset returns no credit: every byte it accounts for is either still to be delivered or already in the receive buffer,
     * the latter being held above `eos` for as long as the stream lives */
    quicly_get_max_data(server, NULL, NULL, &consumed, &shifted);
    ok(consumed == 10);
    ok(shifted == 0);

    /* Completing the committed prefix completes the transfer. The gap keeps `eos` where it is, and the bytes stranded above it
     * are not handed to the application; were they, it would be reading the gap as well. */
    ok(inject_frames(server, prefix, sizeof(prefix)) == 0);
    ok(quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(stream->recvstate.eos == 5);
    ok(quicly_recvstate_bytes_available(&stream->recvstate) == 5);
    ok(quicly_streambuf_ingress_get(stream).len == 5);

    /* consuming what was offered leaves the receive state consistent */
    quicly_streambuf_ingress_shift(stream, quicly_streambuf_ingress_get(stream).len);
    ok(stream->recvstate.data_off == 5);
    ok(quicly_recvstate_bytes_available(&stream->recvstate) == 0);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

static void test_stop_sending_after_reset(int application_reset)
{
    /* STOP_SENDING(id=0, error=11) */
    static const uint8_t stop[] = {0x05, 0x00, 0x0b};
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    uint64_t error_code = application_reset ? 22 : 11;

    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(stream->stream_id == 0);

    if (application_reset)
        quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(error_code));
    ok(inject_frames(client, stop, sizeof(stop)) == 0);
    ok(quicly_sendstate_eos_type(&stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET);
    ok(stream->sendstate.app_error_code == error_code);
    ok(!quicly_sendstate_is_fully_inflight(&stream->sendstate));

    /* a repeated STOP_SENDING is harmless both before the reset is sent and while it awaits acknowledgement */
    ok(inject_frames(client, stop, sizeof(stop)) == 0);
    transmit(client, server);
    ok(stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_INFLIGHT);
    ok(quicly_sendstate_is_fully_inflight(&stream->sendstate));
    /* a RESET_STREAM is not part of the transfer, which is therefore complete from the moment the stream is reset */
    ok(quicly_sendstate_transfer_complete(&stream->sendstate));
    ok(inject_frames(client, stop, sizeof(stop)) == 0);
    ok(stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_INFLIGHT);
    ok(stream->sendstate.app_error_code == error_code);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(quicly_sendstate_transfer_complete(&stream->sendstate));
    ok(stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED);

    quicly_free(client);
    quicly_free(server);
}

static void reset_in_on_send_emit_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    /* act like an application failing to read the payload (e.g., pread(2) returning short as the file shrank) */
    *len = 0;
    *wrote_all = 1;
    quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1));
}

/**
 * When the application resets the stream from within `on_send_emit`, the sentmap entry that has been allocated for the STREAM frame
 * must not be left uninitialized, as it is handled by `on_ack_stream` when the packet is acked or deemed lost.
 */
static void test_reset_in_on_send_emit(void)
{
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    quicly_stream_callbacks_t callbacks = stream_callbacks;
    callbacks.on_send_emit = reset_in_on_send_emit_emit;

    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(client, &stream, 0) == 0);
    stream->callbacks = &callbacks;
    ok(quicly_streambuf_egress_write(stream, "hello", 5) == 0);

    /* fill the unused slots of the sentmap with stale entries of the stream, each carrying an inverted range, so that the test
     * reliably detects use of the entry being left uninitialized */
    struct st_quicly_sent_block_t *tail = client->path_spaces[0]->loss.sentmap.tail;
    ok(tail != NULL && tail->next_insert_at < PTLS_ELEMENTSOF(tail->entries) - 4);
    if (tail != NULL) {
        for (size_t i = tail->next_insert_at; i < PTLS_ELEMENTSOF(tail->entries); ++i) {
            tail->entries[i].acked = on_ack_stream;
            tail->entries[i].data.stream.stream_id = stream->stream_id;
            tail->entries[i].data.stream.args.start = 10;
            tail->entries[i].data.stream.args.end = 5;
            tail->entries[i].data.stream.args.eos_type = QUICLY_SENDSTATE_EOS_TYPE_NONE;
        }
    }

    /* send; the application resets the stream while the STREAM frame is being built */
    transmit(client, server);
    ok(quicly_sendstate_eos_type(&stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET);

    /* the entry allocated for the dropped STREAM frame is a no-op, and the entries of the stream that are in flight carry valid
     * ranges */
    size_t num_noop_entries = 0;
    for (struct st_quicly_sent_block_t *block = client->path_spaces[0]->loss.sentmap.head; block != NULL; block = block->next) {
        for (size_t i = 0; i < block->next_insert_at; ++i) {
            quicly_sent_t *sent = block->entries + i;
            if (sent->acked == on_ack_noop) {
                ++num_noop_entries;
            } else if (sent->acked == on_ack_stream && sent->data.stream.stream_id == stream->stream_id) {
                ok(sent->data.stream.args.start <= sent->data.stream.args.end);
            }
        }
    }
    ok(num_noop_entries == 1);

    /* receive ACK; the client used to trip on the inverted range, then complete the transfer */
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(quicly_sendstate_transfer_complete(&stream->sendstate));

    quicly_free(client);
    quicly_free(server);
}

static void test_stop_sending_after_fin(int fin_state)
{
    /* STOP_SENDING(id=0, error=11) */
    static const uint8_t stop[] = {0x05, 0x00, 0x0b};
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    test_streambuf_t *streambuf;

    test_setup_connected_peers(&client, &server);
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(stream->stream_id == 0);
    streambuf = stream->data;
    ok(quicly_streambuf_egress_write(stream, "hello", 5) == 0);
    ok(quicly_streambuf_egress_shutdown(stream) == 0);
    if (fin_state != QUICLY_SENDSTATE_EOS_STATE_UNSENT)
        transmit(client, server);
    if (fin_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED) {
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        transmit(server, client);
    }
    ok(stream->sendstate.eos_state == fin_state);

    ok(inject_frames(client, stop, sizeof(stop)) == 0);
    if (fin_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED) {
        /* a completed transfer stays complete and does not notify the application */
        ok(quicly_sendstate_eos_type(&stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_FIN);
        ok(quicly_sendstate_transfer_complete(&stream->sendstate));
        ok(streambuf->error_received.stop_sending == -1);
    } else {
        ok(quicly_sendstate_eos_type(&stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET);
        ok(stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT);
        ok(stream->sendstate.app_error_code == 11);
        /* an emitted FIN fixes the final size; an unsent FIN can be withdrawn */
        ok(stream->sendstate.final_size == (fin_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT ? 0 : 5));
        /* the application, having shut down the stream, is not notified, but releases what it was holding */
        ok(streambuf->error_received.stop_sending == -1);
        ok(streambuf->super.egress.vecs.size == 0);
        ok(inject_frames(client, stop, sizeof(stop)) == 0);
        transmit(client, server);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        transmit(server, client);
        ok(quicly_sendstate_transfer_complete(&stream->sendstate));
    }

    quicly_free(client);
    quicly_free(server);
}

/**
 * A FIN below the bytes already received is a FINAL_SIZE_ERROR (RFC 9000 Section 4.5). The final size must not be recorded, as the
 * application might have consumed bytes beyond it.
 */
static void test_fin_below_received(void)
{
    /* STREAM(id=0, len=10), STREAM(id=0, len=5, FIN) */
    static const uint8_t data[] = {0x0a, 0x00, 0x0a, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    static const uint8_t fin[] = {0x0b, 0x00, 0x05, '0', '1', '2', '3', '4'};
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;

    test_setup_connected_peers(&client, &server);

    ok(inject_frames(server, data, sizeof(data)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    quicly_streambuf_ingress_shift(stream, 10);

    ok(inject_frames(server, fin, sizeof(fin)) == QUICLY_TRANSPORT_ERROR_FINAL_SIZE);
    ok(stream->recvstate.eos == UINT64_MAX);
    ok(!quicly_recvstate_transfer_complete(&stream->recvstate));

    quicly_free(client);
    quicly_free(server);
}

/**
 * Returns if the connection-level ingress credit charged is `expected`, and is what has been returned plus what each stream still
 * holds in memory.
 */
static int ingress_credit_is_correct(quicly_conn_t *conn, uint64_t expected)
{
    uint64_t held = 0;
    quicly_stream_t *stream;

    kh_foreach_value(conn->streams, stream, {
        if (stream->stream_id >= 0)
            held += quicly_recvstate_bytes_allocated(&stream->recvstate) - stream->recvstate.data_off;
    });

    return conn->ingress.max_data.bytes_consumed == expected &&
           conn->ingress.max_data.bytes_consumed == conn->ingress.max_data.bytes_shifted + held;
}

#define INGRESS_CREDIT_NUM_EVENTS 16
#define INGRESS_CREDIT_MAX_EVENTS 5

static uint8_t *encode_stream_frame(uint8_t *dst, quicly_stream_id_t stream_id, uint64_t off, const char *data, size_t len,
                                    int is_fin)
{
    *dst++ = QUICLY_FRAME_TYPE_STREAM_BASE | QUICLY_FRAME_TYPE_STREAM_BIT_OFF | QUICLY_FRAME_TYPE_STREAM_BIT_LEN |
             (is_fin ? QUICLY_FRAME_TYPE_STREAM_BIT_FIN : 0);
    dst = quicly_encodev(dst, stream_id);
    dst = quicly_encodev(dst, off);
    dst = quicly_encodev(dst, len);
    memcpy(dst, data, len);
    return dst + len;
}

/**
 * Applies one of the events enumerated by `test_ingress_credit_exhaustive` to a stream of 3 bytes. Returns if successful.
 * `credit_used` is updated to the connection-level credit that the stream uses as defined by RFC 9000 Section 4.5; i.e., the final
 * size if known, otherwise the largest offset received.
 */
static int apply_ingress_credit_event(quicly_conn_t *conn, quicly_stream_id_t stream_id, size_t event, uint64_t *credit_used)
{
    uint8_t frame[32], *dst = frame;
    uint64_t used;

    switch (event) {
    case 0: /* RESET_STREAM */
    case 1:
    case 2:
    case 3: /* RESET_STREAM_AT of Reliable Size 1 to 3 */
        dst = quicly_encode_reset_stream_frame(dst, stream_id, 11, 3, event);
        used = 3;
        break;
    case 4:
    case 5: {
        /* the application consumes one byte, or all the bytes available */
        quicly_stream_t *stream;
        size_t avail;
        if ((stream = quicly_get_stream(conn, stream_id)) != NULL && (avail = quicly_streambuf_ingress_get(stream).len) != 0)
            quicly_streambuf_ingress_shift(stream, event == 4 ? 1 : avail);
        return 1;
    }
    default: {
        /* STREAM frames of each range, with and without FIN */
        static const struct {
            uint8_t off, end, is_fin;
        } streams[] = {{0, 1}, {0, 2}, {0, 3}, {1, 2}, {1, 3}, {2, 3}, {0, 3, 1}, {1, 3, 1}, {2, 3, 1}, {3, 3, 1}};
        PTLS_BUILD_ASSERT(6 + PTLS_ELEMENTSOF(streams) == INGRESS_CREDIT_NUM_EVENTS);
        assert(event - 6 < PTLS_ELEMENTSOF(streams));
        uint8_t off = streams[event - 6].off, end = streams[event - 6].end;
        dst = encode_stream_frame(dst, stream_id, off, &"xyz"[off], end - off, streams[event - 6].is_fin);
        used = end;
    } break;
    }

    if (*credit_used < used)
        *credit_used = used;
    return inject_frames(conn, frame, dst - frame) == 0;
}

/**
 * Applies every sequence of up to INGRESS_CREDIT_MAX_EVENTS events to a unidirectional stream of 3 bytes, the events being the
 * STREAM frames of each range with and without FIN, the FIN-only STREAM frame, RESET_STREAM, RESET_STREAM_AT of each non-zero
 * Reliable Size, and the application consuming one or all the bytes available. The stream being unidirectional, quicly destroys it
 * once all the bytes up to the end of the stream (or to the Reliable Size) are received; if that has not happened after the events,
 * a STREAM frame carrying all the bytes and the FIN is applied to make it happen. After each event, and after the stream is
 * destroyed, the connection-level credit charged is checked against the value defined by RFC 9000 Section 4.5, and against what has
 * been returned plus what the streams still hold. Streams being independent of each other, this covers the credit accounting of any
 * mix of streams up to that length, without relying on chance.
 */
static void test_ingress_credit_exhaustive(void)
{
    quicly_transport_parameters_t orig = quic_ctx.transport_params;
    quicly_stream_callbacks_t callbacks = stream_callbacks;
    quicly_conn_t *client, *server;
    quicly_stream_id_t stream_id = 2; /* client-initiated unidirectional */
    uint64_t num_sequences = 0, credit_used_by_previous = 0;
    int failed = 0;

    callbacks.on_destroy = quicly_streambuf_destroy; /* the default one leaks the buffer, which matters with this many streams */

    /* nothing is sent by the server, hence the limits are set high enough to cover all the sequences */
    quic_ctx.transport_params.reset_stream_at = 1;
    quic_ctx.transport_params.max_streams_uni = 1 << 24;
    quic_ctx.transport_params.max_data = 1 << 30;
    test_setup_connected_peers(&client, &server);

    for (size_t len = 1; len <= INGRESS_CREDIT_MAX_EVENTS; ++len) {
        uint64_t count = 1;
        for (size_t i = 0; i < len; ++i)
            count *= INGRESS_CREDIT_NUM_EVENTS;
        for (uint64_t seq = 0; seq < count; ++seq, stream_id += 4, ++num_sequences) {
            quicly_stream_t *stream;
            uint64_t credit_used = 0;
            if (quicly_get_or_open_stream(server, stream_id, &stream) != 0 || stream == NULL)
                goto Fail;
            stream->callbacks = &callbacks;
            for (uint64_t i = 0, events = seq; i < len; ++i, events /= INGRESS_CREDIT_NUM_EVENTS) {
                if (!apply_ingress_credit_event(server, stream_id, events % INGRESS_CREDIT_NUM_EVENTS, &credit_used) ||
                    !ingress_credit_is_correct(server, credit_used_by_previous + credit_used))
                    goto Fail;
            }
            if (quicly_get_stream(server, stream_id) != NULL) {
                if (!apply_ingress_credit_event(server, stream_id, 12 /* STREAM(off=0, len=3, FIN) */, &credit_used))
                    goto Fail;
                if (quicly_get_stream(server, stream_id) != NULL ||
                    !ingress_credit_is_correct(server, credit_used_by_previous + credit_used))
                    goto Fail;
            }
            credit_used_by_previous += credit_used;
            continue;
        Fail:
            /* stop here, as the connection might have been left in a state that taints the subsequent sequences */
            note("failed at length %zu, sequence %" PRIu64, len, seq);
            failed = 1;
            goto Exit;
        }
    }

Exit:
    ok(!failed);
    note("%" PRIu64 " sequences", num_sequences);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params = orig;
}

/**
 * A reset that completes the transfer by itself, all bytes below its Reliable Size having been received, ends the stream through
 * `on_receive` if the Reliable Size is non-zero, or if `on_receive_reset` is NULL; otherwise through `on_receive_reset`.
 */
static void test_reset_completing_transfer(int reliable_size, int is_reset_stream_at, int null_on_receive_reset)
{
    /* STREAM(id=0, len=3) "abc", then RESET_STREAM_AT(id=0, error=11, final=3, reliable=reliable_size) or
     * RESET_STREAM(id=0, error=11, final=3) */
    static const uint8_t data[] = {0x0a, 0x00, 0x03, 'a', 'b', 'c'};
    const uint8_t reset_at[] = {0x24, 0x00, 0x0b, 0x03, (uint8_t)reliable_size}, reset[] = {0x04, 0x00, 0x0b, 0x03};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    quicly_stream_callbacks_t callbacks;
    test_streambuf_t *streambuf;

    assert(is_reset_stream_at || reliable_size == 0);

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    ok(inject_frames(server, data, sizeof(data)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    streambuf = stream->data;
    ok(!quicly_recvstate_transfer_complete(&stream->recvstate));
    if (null_on_receive_reset) {
        callbacks = *stream->callbacks;
        callbacks.on_receive_reset = NULL;
        stream->callbacks = &callbacks;
    }

    if (is_reset_stream_at) {
        ok(inject_frames(server, reset_at, sizeof(reset_at)) == 0);
    } else {
        ok(inject_frames(server, reset, sizeof(reset)) == 0);
    }
    ok(quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(buffer_is(&streambuf->super.ingress, "abc"));
    if (reliable_size != 0 || null_on_receive_reset) {
        ok(streambuf->error_received.reset_on_receive == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(11));
        ok(streambuf->error_received.reset_stream == -1);
    } else {
        ok(streambuf->error_received.reset_on_receive == -1);
        ok(streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(11));
    }

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

static void test_reset_stream_at_after_fin(void)
{
    /* STREAM(id=0, off=2, len=3, FIN) "234", RESET_STREAM_AT(id=0, error=11, final=5, reliable=5), STREAM(id=0, len=2) "01" */
    static const uint8_t fin_leaving_gap[] = {0x0f, 0x00, 0x02, 0x03, '2', '3', '4'};
    static const uint8_t reset[] = {0x24, 0x00, 0x0b, 0x05, 0x05};
    static const uint8_t fill_gap[] = {0x0a, 0x00, 0x02, '0', '1'};
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    quicly_conn_t *client, *server;
    quicly_stream_t *stream;
    test_streambuf_t *streambuf;

    quic_ctx.transport_params.reset_stream_at = 1;
    test_setup_connected_peers(&client, &server);

    /* the FIN makes the final size known while leaving [0,2) missing */
    ok(inject_frames(server, fin_leaving_gap, sizeof(fin_leaving_gap)) == 0);
    ok((stream = quicly_get_stream(server, 0)) != NULL);
    streambuf = stream->data;
    ok(!quicly_recvstate_transfer_complete(&stream->recvstate));

    /* the reset reduces nothing, its Reliable Size being the Final Size, but its error code is to be retained */
    ok(inject_frames(server, reset, sizeof(reset)) == 0);
    ok(!quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(streambuf->error_received.reset_on_receive == -1);

    /* filling the gap completes the transfer, and it is then that the error code of the reset is surfaced */
    ok(inject_frames(server, fill_gap, sizeof(fill_gap)) == 0);
    ok(quicly_recvstate_transfer_complete(&stream->recvstate));
    ok(streambuf->error_received.reset_on_receive == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(11));

    quicly_free(client);
    quicly_free(server);
    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
}

/**
 * This test checks STATE_EXHAUSTION error is correctly returned to the application, and if the application supplies the error code
 * to quicly, quicly sends a PROTCOL_VIOLATION error with the special reason phrase.
 */
static void test_state_exhaustion(void)
{
    uint64_t orig_max_stream_data_bidi_remote = quic_ctx.transport_params.max_stream_data.bidi_remote;
    quic_ctx.transport_params.max_stream_data.bidi_remote = 65536; /* shrink to reduce # of gaps permitted */

    quicly_conn_t *client, *server;
    quicly_send_context_t s;
    struct iovec datagram;
    uint8_t buf[quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded;
    size_t num_datagrams, num_decoded;
    quicly_address_t dest, src;
    quicly_error_t ret = 0;

    test_setup_connected_peers(&client, &server);

    /* send up to 200 packets with stream frame having gaps and check that the receiver raises state exhaustion */
    for (size_t i = 0; i < 200; ++i) {
        test_setup_send_context(client, &s, &datagram, buf, sizeof(buf));
        do_allocate_frame(client, &s, 100, ALLOCATE_FRAME_TYPE_ACK_ELICITING);
        *s.dst++ = QUICLY_FRAME_TYPE_STREAM_BASE | QUICLY_FRAME_TYPE_STREAM_BIT_OFF | QUICLY_FRAME_TYPE_STREAM_BIT_LEN;
        s.dst = quicly_encodev(s.dst, 0);     /* stream id */
        s.dst = quicly_encodev(s.dst, i * 2); /* off */
        s.dst = quicly_encodev(s.dst, 1);     /* len */
        *s.dst++ = (uint8_t)('a' + (i * 2) % 26);
        commit_send_packet(client, &s, 0);
        unlock_now(client);

        num_decoded = decode_packets(&decoded, &datagram, 1);
        ok(num_decoded == 1);
        if ((ret = quicly_receive(server, NULL, &fake_address.sa, &decoded)) != 0)
            break;
    }
    ok(ret == QUICLY_ERROR_STATE_EXHAUSTION);

    /* upon state exhaustion, the receiving endpoint MAY send CONNECTION_CLOSE (in this test, state-exhaustion is sent) */
    quicly_close(server, ret, NULL);
    num_datagrams = 1;
    ret = quicly_send(server, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    num_decoded = decode_packets(&decoded, &datagram, 1);
    ret = quicly_receive(client, NULL, &fake_address.sa, &decoded);
    ok(ret == 0);
    ok(quicly_get_state(client) == QUICLY_STATE_DRAINING);

    /* sender should have received PROTOCOL_VIOLATION with the special reason phrase */
    uint64_t offending_frame_type;
    const char *reason;
    int is_remote;
    ret = quicly_get_close_reason(client, &offending_frame_type, &reason, &is_remote);
    ok(ret == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
    ok(strcmp(reason, "state exhaustion") == 0);
    ok(is_remote);

    quicly_free(client);
    quicly_free(server);

    quic_ctx.transport_params.max_stream_data.bidi_remote = orig_max_stream_data_bidi_remote;
}

static void do_test_migration_during_handshake(int second_flight_from_orig_address)
{
    quicly_conn_t *client, *server;
    const struct sockaddr_in serveraddr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001), .sin_port = htons(12345)},
                             clientaddr1 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000002), .sin_port = htons(12345)},
                             clientaddr2 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000003), .sin_port = htons(12345)};
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[10];
    uint8_t buf[quic_ctx.transport_params.max_udp_payload_size * 10];
    quicly_decoded_packet_t packets[40];
    size_t num_datagrams, num_packets;
    quicly_error_t ret;

    /* client send first flight */
    ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)&serveraddr, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                         NULL, NULL, NULL);
    ok(ret == 0);
    num_datagrams = 10;
    ret = quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    ok(num_datagrams > 0);

    /* server accepts and responds, but the packets are dropped */
    num_packets = decode_packets(packets, datagrams, num_datagrams);
    ok(num_packets == 1);
    ret = quicly_accept(&server, &quic_ctx, &destaddr.sa, (void *)&clientaddr1, packets, NULL, new_master_id(), NULL, NULL);
    ok(ret == 0);
    num_datagrams = 10;
    ret = quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    ok(num_datagrams > 0);

    /* loop until timeout */
    const struct sockaddr_in *clientaddr = second_flight_from_orig_address ? &clientaddr1 : &clientaddr2;
    while (1) {
        int64_t client_timeout = quicly_get_first_timeout(client), server_timeout = quicly_get_first_timeout(server),
                smaller_timeout = client_timeout < server_timeout ? client_timeout : server_timeout;
        if (quic_now < smaller_timeout)
            quic_now = smaller_timeout;

        /* when client times out, it resends Initials but from a different address and the server drops them */
        if (quic_now >= client_timeout) {
            num_datagrams = 10;
            ret = quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
            if (ret == QUICLY_ERROR_FREE_CONNECTION)
                break;
            ok(ret == 0);
            ok(num_datagrams > 0);
            num_packets = decode_packets(packets, datagrams, num_datagrams);
            ok(num_packets > 0);
            for (size_t i = 0; i < num_packets; ++i) {
                ret = quicly_receive(server, (void *)&serveraddr, (void *)clientaddr, &packets[i]);
                if (clientaddr == &clientaddr1) {
                    ok(ret == 0);
                } else {
                    ok(ret == QUICLY_ERROR_PACKET_IGNORED);
                }
            }
            clientaddr = &clientaddr2;
        }

        /* when server times out it resends packets to the old client address */
        if (quic_now >= server_timeout) {
            num_datagrams = 10;
            ret = quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
            if (ret == QUICLY_ERROR_FREE_CONNECTION)
                break;
            ok(ret == 0);
            ok(num_datagrams > 0);
            ok(destaddr.sin.sin_family == AF_INET);
            ok(destaddr.sin.sin_addr.s_addr == clientaddr1.sin_addr.s_addr);
        }
    }

    quicly_free(client);
    quicly_free(server);
}

static void test_amplification_blocked_handshake_timeout(void)
{
    uint32_t orig_handshake_timeout_rtt_multiplier = quic_ctx.handshake_timeout_rtt_multiplier;
    quic_ctx.handshake_timeout_rtt_multiplier = 1;

    quicly_conn_t *client, *server;
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[4];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded[4];

    ok(quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                      NULL, NULL) == 0);
    size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 1);
    ok(decode_packets(decoded, datagrams, num_datagrams) == 1);
    ok(quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL, NULL) == 0);

    struct st_quicly_conn_path_t *server_path = get_path(server, 0);
    server_path->bytes_sent = server_path->bytes_received * quic_ctx.pre_validation_amplification_limit;
    ok(calc_amplification_limit_allowance(server, server_path) == 0);
    quic_now =
        server->created_at + (int64_t)(quic_ctx.handshake_timeout_rtt_multiplier * server->path_spaces[0]->loss.rtt.smoothed);
    ok(quicly_get_first_timeout(server) > quic_now);

    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == QUICLY_ERROR_FREE_CONNECTION);
    ok(num_datagrams == 0);
    ok(quicly_get_state(server) == QUICLY_STATE_DRAINING);

    quicly_free(client);
    quicly_free(server);
    quic_ctx.handshake_timeout_rtt_multiplier = orig_handshake_timeout_rtt_multiplier;
}

static void test_migration_during_handshake(void)
{
    subtest("migrate-before-2nd", do_test_migration_during_handshake, 0);
    subtest("migrate-before-3nd", do_test_migration_during_handshake, 1);
}

/**
 * When a PATH_CHALLENGE is to be sent on a backup path at the moment the loss timer fires, the timer is handled when sending
 * packets on the primary path, rather than being consumed while sending the probe on the backup path.
 */
static void test_pto_with_backup_path_probe(void)
{
    quicly_conn_t *client, *server;
    struct sockaddr_in newaddr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000002), .sin_port = htons(12345)};
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[8];
    uint8_t buf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 4];
    size_t num_datagrams, num_decoded;
    quicly_stream_t *stream;

    test_setup_connected_peers(&client, &server);

    /* server sends stream data that gets lost, arming the loss timer */
    ok(quicly_open_stream(server, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "a", 1) == 0);
    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 1);
    ok(server->path_spaces[0]->loss.alarm_at != INT64_MAX);

    /* when the loss timer fires, a packet from a new client address arrives, scheduling a PATH_CHALLENGE on a backup path */
    quic_now = server->path_spaces[0]->loss.alarm_at;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, "a", 1) == 0);
    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 1);
    num_decoded = decode_packets(decoded, datagrams, num_datagrams);
    for (size_t i = 0; i != num_decoded; ++i)
        ok(quicly_receive(server, NULL, (void *)&newaddr, decoded + i) == 0);
    ok(server->path_spaces[0]->addrs[1] != NULL);
    ok(server->path_spaces[0]->loss.alarm_at <= quic_now);
    int8_t pto_count = server->path_spaces[0]->loss.pto_count;

    /* server sends a PATH_CHALLENGE on the backup path, without consuming the loss timer */
    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams == 1);
    ok(compare_socket_address(&destaddr.sa, (void *)&newaddr) == 0);
    ok(server->path_spaces[0]->loss.pto_count == pto_count);
    ok(server->path_spaces[0]->loss.alarm_at <= quic_now);

    /* then, sends the PTO probe on the primary path */
    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf)) == 0);
    ok(num_datagrams != 0);
    ok(compare_socket_address(&destaddr.sa, &fake_address.sa) == 0);
    ok(server->path_spaces[0]->loss.pto_count != pto_count);
    ok(quic_now < server->path_spaces[0]->loss.alarm_at);

    quicly_free(client);
    quicly_free(server);
}

static size_t test_stats_foreach_next_off;

static void test_stats_foreach_field(size_t off, size_t size)
{
    ok(test_stats_foreach_next_off == off);

    /* The RTT floor's sampling state is internal, not a set of exported statistics. */
    if (off == offsetof(quicly_stats_t, rtt.latest)) {
        test_stats_foreach_next_off = offsetof(quicly_stats_t, loss_thresholds.use_packet_based);
        return;
    }

    /* Due to alignment, padding might exist between two fields when their types are different. The `gaps` list calls out the ones
     * that "might" have such padding on some architectures. */
    static const size_t gaps[] = {
#define GAP(after, before) offsetof(quicly_stats_t, after), offsetof(quicly_stats_t, before)
        GAP(jumpstart.cwnd, token_sent.at),
        GAP(token_sent.rtt, rtt.minimum),
        GAP(loss_thresholds.use_packet_based, loss_thresholds.time_based_percentile),
        GAP(loss_thresholds.time_based_percentile, cc.cwnd),
        GAP(cc.ssthresh, cc.cwnd_initial),
        GAP(cc.cwnd_exiting_slow_start, cc.exit_slow_start_at),
#undef GAP
        SIZE_MAX};
    for (size_t i = 0; gaps[i] != SIZE_MAX; i += 2) {
        if (test_stats_foreach_next_off == gaps[i]) {
            test_stats_foreach_next_off = gaps[i + 1];
            return;
        }
    }

    /* otherwise, it is right after the current field */
    test_stats_foreach_next_off += size;
}

static void test_stats_foreach(void)
{
#define CHECK(fld, name)                                                                                                           \
    subtest(name, test_stats_foreach_field, offsetof(quicly_stats_t, fld), sizeof(((quicly_stats_t *)NULL)->fld));

    /* check QUICLY_STATS_FOREACH touches all fields, in the correct order */
    test_stats_foreach_next_off = 0;
    QUICLY_STATS_FOREACH(CHECK);
    ok(test_stats_foreach_next_off == sizeof(quicly_stats_t));

    /* check QUICLY_STATS_FOREACH_COUNTERS only check the counters */
    struct counters_only {
        QUICLY_STATS_PREBUILT_COUNTERS;
    };
    test_stats_foreach_next_off = 0;
    QUICLY_STATS_FOREACH_COUNTERS(CHECK);
    ok(test_stats_foreach_next_off == sizeof(struct counters_only));

#undef CHECK
}

static struct sockaddr_in loopback_addr(uint16_t port)
{
    return (struct sockaddr_in){.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
}

static size_t transmit_multipath_with_loss(quicly_conn_t *src, quicly_conn_t *dst, int drop_src_port)
{
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[32];
    uint8_t datagramsbuf[PTLS_ELEMENTSOF(datagrams) * quicly_get_context(src)->transport_params.max_udp_payload_size];
    size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 2];

    ok(quicly_send(src, &destaddr, &srcaddr, datagrams, &num_datagrams, datagramsbuf, sizeof(datagramsbuf)) == 0);
    if (num_datagrams != 0) {
        if (drop_src_port >= 0 && ntohs(srcaddr.sin.sin_port) == drop_src_port)
            return 0;
        size_t num_packets = decode_packets(decoded, datagrams, num_datagrams);
        for (size_t i = 0; i != num_packets; ++i) {
            quicly_error_t ret = quicly_receive(dst, &destaddr.sa, &srcaddr.sa, decoded + i);
            ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
        }
    }
    return num_datagrams;
}

static size_t transmit_multipath(quicly_conn_t *src, quicly_conn_t *dst)
{
    return transmit_multipath_with_loss(src, dst, -1);
}

static void multipath_round(quicly_conn_t *client, quicly_conn_t *server, int client_drop_port, int server_drop_port)
{
    ++quic_now;
    transmit_multipath_with_loss(client, server, client_drop_port);
    transmit_multipath_with_loss(server, client, server_drop_port);
}

static void multipath_run(quicly_conn_t *client, quicly_conn_t *server, size_t rounds, int client_drop_port, int server_drop_port)
{
    for (size_t i = 0; i < rounds; ++i)
        multipath_round(client, server, client_drop_port, server_drop_port);
}

static void open_multipath_test_path(quicly_conn_t *client)
{
    struct sockaddr_in remote = loopback_addr(10000), local = loopback_addr(20000);
    ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
}

static quicly_cid_encryptor_t *new_test_mp_encryptor(void)
{
    static const char key[] = "0123456789abcdef";
    return quicly_new_default_cid_encryptor(&ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                            ptls_iovec_init(key, sizeof(key) - 1));
}

static quicly_context_t setup_multipath_regression_peers_limit(quicly_conn_t **client, quicly_conn_t **server,
                                                               int disable_migration, uint64_t max_path_id)
{
    quicly_context_t saved = quic_ctx;
    quic_ctx.transport_params.initial_max_path_id = max_path_id;
    quic_ctx.transport_params.disable_active_migration = disable_migration;
    quic_ctx.cid_encryptor = new_test_mp_encryptor();
    test_setup_connected_peers(client, server);
    get_path(*client, 0)->address.local = get_path(*client, 0)->address.remote = fake_address;
    get_path(*server, 0)->address.local = get_path(*server, 0)->address.remote = fake_address;
    return saved;
}

static quicly_context_t setup_multipath_regression_peers(quicly_conn_t **client, quicly_conn_t **server, int disable_migration)
{
    return setup_multipath_regression_peers_limit(client, server, disable_migration, 4);
}

static void free_multipath_regression_peers(quicly_conn_t *client, quicly_conn_t *server, quicly_context_t saved)
{
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
}

static void setup_asymmetric_peers(quicly_conn_t **client, quicly_conn_t **server, quicly_context_t *client_ctx,
                                   quicly_context_t *server_ctx, int client_cid, int server_cid)
{
    quicly_address_t dest, src;
    struct iovec dgrams[8];
    uint8_t buf[PTLS_ELEMENTSOF(dgrams) * 1500];
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(dgrams) * 4];
    size_t count = PTLS_ELEMENTSOF(dgrams);

    ok(quicly_connect(client, client_ctx, "example.com", &fake_address.sa, NULL, client_cid ? new_master_id() : NULL,
                      ptls_iovec_init(NULL, 0), NULL, NULL, NULL) == 0);
    ok(quicly_send(*client, &dest, &src, dgrams, &count, buf, sizeof(buf)) == 0 && count == 1);
    ok(decode_packets(decoded, dgrams, 1) == 1);
    ok(quicly_accept(server, server_ctx, NULL, &fake_address.sa, decoded, NULL, server_cid ? new_master_id() : NULL, NULL, NULL) ==
       0);
    if (quicly_get_state(*server) == QUICLY_STATE_CONNECTED) {
        ok(transmit(*server, *client) > 0);
        exchange_until_idle(*client, *server);
        get_path(*client, 0)->address.local = get_path(*client, 0)->address.remote = fake_address;
        get_path(*server, 0)->address.local = get_path(*server, 0)->address.remote = fake_address;
    }
}

static quicly_error_t send_raw_1rtt_frame(quicly_conn_t *src, quicly_conn_t *dst, size_t send_path, struct sockaddr *dest_sa,
                                          struct sockaddr *src_sa, const void *frame_bytes, size_t frame_len)
{
    quicly_send_context_t s;
    struct iovec datagram;
    uint8_t buf[1500];
    quicly_decoded_packet_t decoded;

    test_setup_send_context(src, &s, &datagram, buf, sizeof(buf));
    s.path_index = send_path;
    if (get_path(src, send_path)->dcid == UINT64_MAX)
        ok(setup_path_dcid(src, send_path));
    s.dcid = get_dcid(src, send_path);
    ok(do_allocate_frame(src, &s, frame_len, ALLOCATE_FRAME_TYPE_ACK_ELICITING) == 0);
    memcpy(s.dst, frame_bytes, frame_len);
    s.dst += frame_len;
    ok(commit_send_packet(src, &s, 0) == 0);
    if (get_path(src, send_path) == get_path(src, send_path)->path_space->addrs[0])
        update_send_alarm(src, scheduler_can_send(src), get_path(src, send_path)->path_space);
    unlock_now(src);
    ok(decode_packets(&decoded, &datagram, 1) == 1);
    return quicly_receive(dst, dest_sa, src_sa, &decoded);
}

static size_t multipath_received_length(quicly_conn_t *conn, quicly_stream_id_t stream_id)
{
    quicly_stream_t *stream = quicly_get_stream(conn, stream_id);
    return stream != NULL ? quicly_streambuf_ingress_get(stream).len : 0;
}

static void test_queue_receive_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    (void)self;
    (void)conn;
    (void)payload;
}

static size_t test_rr_next_path_index;

static quicly_error_t test_round_robin_path_scheduler_do_send(quicly_path_scheduler_t *sched, quicly_conn_t *conn,
                                                              quicly_send_context_t *s)
{
    (void)sched;
    if (!quicly_is_multipath(conn))
        return quicly_send_on_path(conn, s, 0, NULL);

    unsigned preferred_rank = UINT_MAX;
    for (size_t i = 0; i < QUICLY_MAX_PATHS; ++i) {
        quicly_path_stats_t st;
        if (quicly_is_path_available(conn, i) && quicly_get_path_stats(conn, i, &st) == 0 && !st.probe_only) {
            unsigned rank = (st.pto_count >= 2 ? (unsigned)st.pto_count * 2 : 0) + st.peer_is_backup;
            if (rank < preferred_rank)
                preferred_rank = rank;
        }
    }
    for (size_t i = 0; i < QUICLY_MAX_PATHS; ++i) {
        size_t index = (test_rr_next_path_index + i) % QUICLY_MAX_PATHS;
        quicly_path_stats_t st;
        if (!quicly_is_path_available(conn, index) || quicly_get_path_stats(conn, index, &st) != 0)
            continue;
        unsigned rank = (st.pto_count >= 2 ? (unsigned)st.pto_count * 2 : 0) + st.peer_is_backup;
        if (rank != preferred_rank && quicly_get_num_datagram_frames_path(conn, index) == 0)
            continue;
        size_t sent = 0;
        quicly_error_t ret = quicly_send_on_path(conn, s, index, &sent);
        if (ret != 0)
            return ret;
        if (sent != 0) {
            test_rr_next_path_index = (index + 1) % QUICLY_MAX_PATHS;
            return 0;
        }
    }
    return 0;
}

static quicly_path_scheduler_t test_round_robin_path_scheduler = {test_round_robin_path_scheduler_do_send};

static quicly_context_t setup_multipath_scheduling_peers(quicly_conn_t **client, quicly_conn_t **server,
                                                         quicly_path_scheduler_t *scheduler)
{
    quicly_context_t saved = setup_multipath_regression_peers(client, server, 0);
    quic_ctx.path_scheduler = scheduler;
    open_multipath_test_path(*client);
    multipath_run(*client, *server, 100, -1, -1);
    ok(quicly_is_path_available(*client, 1));
    ok(quicly_set_path_status(*server, 1, 1) == 0);
    multipath_run(*server, *client, 100, -1, -1);
    ok((*client)->path_spaces[1]->is_backup);
    return saved;
}

static void deliver_multipath_cid(quicly_conn_t *src, quicly_conn_t *dst, size_t send_path, uint32_t path_id, uint64_t sequence,
                                  int legacy, const uint8_t token[16])
{
    uint8_t frame[64], *p = frame, cid[8];
    memset(cid, 0xab, sizeof(cid));
    cid[0] = (uint8_t)path_id;
    cid[1] = (uint8_t)sequence;
    if (!legacy) {
        p = quicly_encodev(p, QUICLY_FRAME_TYPE_PATH_NEW_CONNECTION_ID);
        p = quicly_encodev(p, path_id);
    }
    uint8_t *start = p;
    p = quicly_encode_new_connection_id_frame(start, sequence, 0, cid, sizeof(cid), token);
    if (!legacy) {
        memmove(start, start + 1, p - start - 1);
        --p;
    }
    ok(send_raw_1rtt_frame(src, dst, send_path, NULL, &fake_address.sa, frame, (size_t)(p - frame)) == 0);
}

static void multipath_progress_deliver_response(quicly_conn_t *conn, size_t index, const uint8_t *data)
{
    struct st_quicly_handle_payload_state_t state = {
        .path_index = index, .src = data, .end = data + QUICLY_PATH_CHALLENGE_DATA_LEN};
    ok(handle_path_response_frame(conn, &state) == 0);
}

/* lifecycle traversal preserves epoch isolation, PTO credit, and late-ACK state */
static unsigned path_sentmap_callbacks;
static quicly_error_t path_sentmap_error;

static quicly_error_t path_sentmap_on_update(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked,
                                             quicly_sent_t *sent)
{
    (void)map;
    (void)acked;
    (void)sent;
    path_sentmap_callbacks |= 1u << packet->packet_number;
    return path_sentmap_error;
}

static void test_path_sentmap(void)
{
    quicly_conn_t conn = {.super = {.state = QUICLY_STATE_CONNECTED}, .stash = {.now = 1}};
    quicly_path_space_t ps = {0};
    quicly_loss_init(&ps.loss, &quic_ctx.egress[0].loss, 100, &conn.super.remote.transport_params.max_ack_delay,
                     &conn.super.remote.transport_params.ack_delay_exponent);
    path_sentmap_callbacks = 0;
    path_sentmap_error = 0;
    for (uint64_t pn = 0; pn < 4; ++pn) {
        ok(quicly_sentmap_prepare(&ps.loss.sentmap, pn, 1, pn == 0 ? QUICLY_EPOCH_INITIAL : QUICLY_EPOCH_1RTT) == 0);
        ok(quicly_sentmap_allocate(&ps.loss.sentmap, path_sentmap_on_update) != NULL);
        quicly_sentmap_commit(&ps.loss.sentmap, 100, 0);
    }
    size_t budget = 100;
    ok(mark_frames_on_pto(&conn, &ps, QUICLY_EPOCH_1RTT, &budget) == 0 && budget == 0 && path_sentmap_callbacks == 2);
    ok(ps.loss.sentmap.bytes_in_flight == 400 && ps.loss.sentmap.num_packets == 4);
    path_sentmap_callbacks = 0;
    budget = 150;
    ok(mark_frames_on_pto(&conn, &ps, QUICLY_EPOCH_1RTT, &budget) == 0 && budget == 0 && path_sentmap_callbacks == 12);
    path_sentmap_callbacks = 0;
    budget = 100;
    ok(mark_frames_on_pto(&conn, &ps, QUICLY_EPOCH_1RTT, &budget) == 0 && budget == 100 && path_sentmap_callbacks == 0);
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_EXPIRED, 1u << QUICLY_EPOCH_1RTT, NULL, 0) == 0);
    ok(ps.loss.sentmap.num_packets == 1 && ps.loss.sentmap.bytes_in_flight == 100);
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_LOST, ~0u, NULL, 0) == 0 && path_sentmap_callbacks == 1);
    ok(ps.loss.sentmap.num_packets == 1 && ps.loss.sentmap.bytes_in_flight == 0);
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_EXPIRED, ~0u, NULL, 0) == 0 && ps.loss.sentmap.num_packets == 0);
    ok(quicly_sentmap_prepare(&ps.loss.sentmap, 4, 1, QUICLY_EPOCH_1RTT) == 0);
    ok(quicly_sentmap_allocate(&ps.loss.sentmap, path_sentmap_on_update) != NULL);
    quicly_sentmap_commit(&ps.loss.sentmap, 0, 0);
    conn.super.state = QUICLY_STATE_CLOSING;
    conn.stash.now = 100000;
    path_sentmap_callbacks = 0;
    path_sentmap_error = PTLS_ERROR_NO_MEMORY;
    ok(update_path_sentmap(&conn, &ps, QUICLY_SENTMAP_EVENT_LOST, ~0u, NULL, 1) == PTLS_ERROR_NO_MEMORY);
    ok(path_sentmap_callbacks == 16);
    quicly_loss_dispose(&ps.loss);
    path_sentmap_error = 0;
}

static void test_datagram_queue(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t saved = quic_ctx;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.max_datagram_frame_payloads = 64;
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;

    quicly_conn_t queue_owner = {.super.ctx = &quic_ctx};
    quicly_datagram_queue_t queue = {0};
    ptls_iovec_t empty = ptls_iovec_init(NULL, 0);
    ok(enqueue_datagram_queue(&queue_owner, &queue, &empty, 1) == 1 && queue.capacity == 8);
    ptls_iovec_t batch[64] = {{0}};
    ok(enqueue_datagram_queue(&queue_owner, &queue, batch, PTLS_ELEMENTSOF(batch)) == 63 && queue.capacity == 64);
    clear_datagram_queue(&queue);

    /* partial send, refill, and unsent suffix cleanup */
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    exchange_until_idle(client, server);
    uint8_t bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(bytes, sizeof(bytes));
    ok(client->egress.datagram_frame_payloads.entries == NULL);
    size_t capacity = quicly_get_max_datagram_frames_path(client, 0);
    for (size_t i = 0; i < capacity + 1; ++i)
        quicly_send_datagram_frames(client, &payload, 1);
    ok(client->egress.datagram_frame_payloads.entries != NULL && server->egress.datagram_frame_payloads.entries == NULL);
    ok(client->egress.datagram_frame_payloads.count == capacity && quicly_get_num_datagram_frames_path(client, 0) == 0);
    quicly_address_t dest, src;
    struct iovec datagrams[2];
    uint8_t buffer[3000];
    size_t count = PTLS_ELEMENTSOF(datagrams);
    uint64_t frames = client->super.stats.num_frames_sent.datagram;
    ok(quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) == 0);
    ok(count > 0 && count < capacity && client->egress.datagram_frame_payloads.count == capacity - count);
    ok(client->super.stats.num_frames_sent.datagram - frames == count);
    for (size_t i = 0; i < count; ++i)
        quicly_send_datagram_frames(client, &payload, 1);
    ok(client->egress.datagram_frame_payloads.count == capacity);
    quicly_send_datagram_frames_path(client, 0, &payload, 1);
    ok(quicly_get_num_datagram_frames_path(client, 0) == 1 &&
       quicly_get_num_datagram_frames_path(client, 0) <= quicly_get_max_datagram_frames_path(client, 0));
    quicly_free(client);
    quicly_free(server);

    /* FIFO ring wrap across capacities 1..3 and invalid overflow capacities */
    for (size_t cap = 1; cap <= 3; ++cap) {
        quicly_context_t ctx = quic_ctx;
        ctx.max_datagram_frame_payloads = cap;
        quicly_conn_t conn = {.super = {.ctx = &ctx}};
        quicly_path_space_t ps = {0};
        struct st_quicly_conn_path_t path = {.path_space = &ps};
        conn.path_spaces[0] = &ps;
        ps.addrs[0] = &path;
        ok(quicly_get_max_datagram_frames_path(&conn, 0) == cap);
        quicly_send_datagram_frames_path(&conn, 0, NULL, 0);
        ok(ps.datagram_frame_payloads.entries == NULL);
        for (size_t i = 0; i <= cap; ++i) {
            uint8_t v = (uint8_t)i;
            ptls_iovec_t p = ptls_iovec_init(&v, 1);
            quicly_send_datagram_frames_path(&conn, 0, &p, 1);
        }
        ok(quicly_get_num_datagram_frames_path(&conn, 0) == cap);
        ps.datagram_frame_payloads.entries[ps.datagram_frame_payloads.head].consumed = 1;
        consume_marked_datagrams(&ps.datagram_frame_payloads);
        uint8_t v = (uint8_t)cap;
        ptls_iovec_t p = ptls_iovec_init(&v, 1);
        quicly_send_datagram_frames_path(&conn, 0, &p, 1);
        for (size_t i = 1; i <= cap; ++i) {
            ptls_iovec_t first = ps.datagram_frame_payloads.entries[ps.datagram_frame_payloads.head].payload;
            ok(first.len == 1 && *(uint8_t *)first.base == i);
            ps.datagram_frame_payloads.entries[ps.datagram_frame_payloads.head].consumed = 1;
            consume_marked_datagrams(&ps.datagram_frame_payloads);
        }
        ok(quicly_get_num_datagram_frames_path(&conn, 0) == 0);
        clear_datagram_queue(&ps.datagram_frame_payloads);
        ok(ps.datagram_frame_payloads.entries == NULL);
    }
    {
        quicly_context_t ctx = quic_ctx;
        quicly_conn_t conn = {.super = {.ctx = &ctx}};
        quicly_path_space_t ps = {0};
        struct st_quicly_conn_path_t path = {.path_space = &ps};
        conn.path_spaces[0] = &ps;
        ps.addrs[0] = &path;
        ptls_iovec_t payloads[] = {ptls_iovec_init("a", 1), ptls_iovec_init("b", 1)};
        size_t bad[] = {SIZE_MAX / sizeof(ps.datagram_frame_payloads.entries[0]) + 1, SIZE_MAX};
        for (size_t i = 0; i < PTLS_ELEMENTSOF(bad); ++i) {
            ctx.max_datagram_frame_payloads = bad[i];
            quicly_send_datagram_frames_path(&conn, 0, payloads, 2);
            ok(ps.datagram_frame_payloads.entries == NULL);
        }
        ctx.max_datagram_frame_payloads = 2;
        quicly_send_datagram_frames_path(&conn, 0, payloads, 2);
        ok(quicly_get_num_datagram_frames_path(&conn, 0) == 2);
        clear_datagram_queue(&ps.datagram_frame_payloads);

        /* sparse datagram queue detection across connection and all path spaces */
        conn.path_spaces[0] = NULL;
        ok(!quicly_has_datagram_frames(&conn));
        for (size_t i = 0; i < PTLS_ELEMENTSOF(conn.path_spaces); ++i) {
            conn.path_spaces[i] = &ps;
            ps.datagram_frame_payloads.count = 0;
            ok(!quicly_has_datagram_frames(&conn));
            ps.datagram_frame_payloads.count = 1;
            ok(quicly_has_datagram_frames(&conn));
            conn.path_spaces[i] = NULL;
        }
    }

    /* oversized drop on idle/multi-path queues and unqualified vs explicit queue separation on path 0 abandonment */
    quicly_context_t mp_saved = setup_multipath_regression_peers(&client, &server, 0);
    open_multipath_test_path(client);
    multipath_run(client, server, 25, -1, -1);
    uint8_t oversized_buf[1300] = {0};
    ptls_iovec_t oversized = ptls_iovec_init(oversized_buf, sizeof(oversized_buf)), small_dg = ptls_iovec_init("ok", 2);
    quicly_send_datagram_frames_path(client, 0, &oversized, 1);
    count = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) == 0);
    ok(quicly_get_num_datagram_frames_path(client, 0) == 0 && quicly_get_first_timeout(client) > quic_now);

    quicly_send_datagram_frames_path(client, 0, &oversized, 1);
    quicly_send_datagram_frames_path(client, 1, &small_dg, 1);
    client->path_spaces[0]->loss.rtt.smoothed = 1;
    client->path_spaces[1]->loss.rtt.smoothed = 50;
    count = PTLS_ELEMENTSOF(datagrams);
    ok(quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) == 0 && count == 1);
    ok(quicly_get_num_datagram_frames_path(client, 0) == 0 && quicly_get_num_datagram_frames_path(client, 1) == 0);

    /* queue unqualified + explicit on path 0 and explicit on path 1, then abandon path 0:
     * explicit path-0 payload is cleared while both path-1 explicit and unqualified payloads are delivered */
    quicly_send_datagram_frames(client, &small_dg, 1);
    quicly_send_datagram_frames_path(client, 0, &small_dg, 1);
    quicly_send_datagram_frames_path(client, 1, &small_dg, 1);
    uint64_t sent_dgs_before = client->super.stats.num_frames_sent.datagram;
    ok(quicly_abandon_path(client, 0, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
    ok(quicly_get_num_datagram_frames_path(client, 0) == 0 && quicly_get_num_datagram_frames_path(client, 1) == 1);
    multipath_run(client, server, 20, -1, -1);
    ok(!quicly_has_datagram_frames(client) && client->super.stats.num_frames_sent.datagram == sent_dgs_before + 2);
    free_multipath_regression_peers(client, server, mp_saved);

    quic_ctx = saved;
    quic_now = saved_now;
}

typedef struct st_cc_test_datagram_t {
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t buf[1500];
} cc_test_datagram_t;

static void cc_test_send_queued_datagram(quicly_conn_t *client, size_t path_index, cc_test_datagram_t *packet)
{
    size_t queued = quicly_get_num_datagram_frames_path(client, path_index), count = 1;
    ok(queued != 0);
    test_rr_next_path_index = path_index;
    packet->datagram = (struct iovec){NULL, 0};
    ok(quicly_send(client, &packet->dest, &packet->src, &packet->datagram, &count, packet->buf, sizeof(packet->buf)) == 0 &&
       count == 1);
    ok(quicly_get_num_datagram_frames_path(client, path_index) == queued - 1);
}

static void cc_test_send_datagram(quicly_conn_t *client, size_t path_index, cc_test_datagram_t *packet)
{
    uint8_t bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(bytes, sizeof(bytes));
    quicly_send_datagram_frames_path(client, path_index, &payload, 1);
    cc_test_send_queued_datagram(client, path_index, packet);
}

static void cc_test_receive_datagram(quicly_conn_t *server, cc_test_datagram_t *packet)
{
    if (packet->datagram.iov_len != 0) {
        quicly_decoded_packet_t decoded;
        ok(decode_packets(&decoded, &packet->datagram, 1) == 1);
        ok(quicly_receive(server, &packet->dest.sa, &packet->src.sa, &decoded) == 0);
    }
}

static void do_test_multipath_cc_limited(size_t busy_path)
{
    quicly_context_t original = quic_ctx;
    int64_t saved_now = quic_now;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.max_datagram_frame_payloads = 2;
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_reno_init;
    quic_ctx.egress[0].cc.initcwnd_packets = 8;
    quic_ctx.egress[0].pacing = 0;
    test_rr_next_path_index = 0;
    quic_ctx.path_scheduler = &test_round_robin_path_scheduler;
    quicly_conn_t *client, *server;
    quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
    open_multipath_test_path(client);
    multipath_run(client, server, 100, -1, -1);

    size_t idle_path = 1 - busy_path;
    quicly_path_space_t *busy = client->path_spaces[busy_path], *idle = client->path_spaces[idle_path];
    uint32_t busy_cwnd = busy->cc.cwnd, idle_cwnd = idle->cc.cwnd, mtu = busy->max_udp_payload_size;
    uint64_t busy_acked = busy->num_packets.bytes_acked;

    cc_test_datagram_t small[2], flight[64], queued[2];
    cc_test_send_datagram(client, idle_path, &small[0]);
    size_t num_packets = 0;
    while (busy->loss.sentmap.bytes_in_flight < busy_cwnd && num_packets != PTLS_ELEMENTSOF(flight))
        cc_test_send_datagram(client, busy_path, &flight[num_packets++]);
    cc_test_send_datagram(client, idle_path, &small[1]);
    for (size_t i = 0; i != 2; ++i) {
        cc_test_receive_datagram(server, &small[i]);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit_multipath(server, client) != 0);
        ok(idle->cc.cwnd == idle_cwnd && busy->cc.cwnd == busy_cwnd);
    }

    uint8_t bytes[1000] = {0};
    ptls_iovec_t idle_payload = ptls_iovec_init(bytes, sizeof(bytes));
    quicly_send_datagram_frames_path(client, idle_path, &idle_payload, 1);
    for (size_t i = 0; i != num_packets; ++i) {
        cc_test_receive_datagram(server, &flight[i]);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit_multipath(server, client) != 0);
        ok(busy->cc.cwnd == busy_cwnd + (busy->num_packets.bytes_acked - busy_acked) / mtu * mtu);
        ok(idle->cc.cwnd == idle_cwnd);
    }
    ok(busy->cc.cwnd > busy_cwnd);
    busy_cwnd = busy->cc.cwnd;

    /* resume below half cwnd while other path's datagram remains queued; ACKs must not grow cwnd */
    for (size_t i = 0; i != 2; ++i)
        cc_test_send_datagram(client, busy_path, &small[i]);
    for (size_t i = 0; i != 2; ++i) {
        cc_test_receive_datagram(server, &small[i]);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit_multipath(server, client) != 0);
        ok(busy->cc.cwnd == busy_cwnd && idle->cc.cwnd == idle_cwnd);
    }

    /* keep DATAGRAMs queued behind a second full window; burst after draining is app-limited */
    num_packets = 0;
    while (busy->loss.sentmap.bytes_in_flight < busy_cwnd && num_packets != PTLS_ELEMENTSOF(flight))
        cc_test_send_datagram(client, busy_path, &flight[num_packets++]);
    ptls_iovec_t payloads[2] = {idle_payload, idle_payload};
    quicly_send_datagram_frames_path(client, busy_path, payloads, 2);
    for (size_t i = 0; i != num_packets; ++i) {
        cc_test_receive_datagram(server, &flight[i]);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit_multipath(server, client) != 0);
    }
    busy_cwnd = busy->cc.cwnd;
    for (size_t i = 0; i != 2; ++i)
        cc_test_send_queued_datagram(client, busy_path, &queued[i]);
    for (size_t i = 0; i != 2; ++i)
        cc_test_send_datagram(client, busy_path, &small[i]);
    for (size_t i = 0; i != 2; ++i) {
        cc_test_receive_datagram(server, &queued[i]);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit_multipath(server, client) != 0);
    }
    ok(busy->cc.cwnd > busy_cwnd);
    busy_cwnd = busy->cc.cwnd;
    for (size_t i = 0; i != 2; ++i) {
        cc_test_receive_datagram(server, &small[i]);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        ok(transmit_multipath(server, client) != 0);
        ok(busy->cc.cwnd == busy_cwnd && idle->cc.cwnd == idle_cwnd);
    }
    ok(quicly_get_num_datagram_frames_path(client, idle_path) == 1);
    free_multipath_regression_peers(client, server, saved);
    quic_ctx = original;
    quic_now = saved_now;
}

static void test_datagram_congestion(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t saved_ctx = quic_ctx;
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;

    /* reno & CUBIC window saturation and cc_limited accounting */
    quicly_init_cc_t *ccs[] = {&quicly_cc_reno_init, &quicly_cc_cubic_init};
    uint8_t payload_bytes[1000] = {0};
    ptls_iovec_t payload = ptls_iovec_init(payload_bytes, sizeof(payload_bytes));
    for (size_t c = 0; c < PTLS_ELEMENTSOF(ccs); ++c) {
        quic_ctx.egress[0].cc.init_cc = ccs[c];
        quicly_conn_t *client, *server;
        test_setup_connected_peers(&client, &server);
        exchange_until_idle(client, server);
        quicly_path_space_t *ps = client->path_spaces[0];
        uint32_t cwnd = ps->cc.cwnd;
        size_t emitted = 0;
        for (; emitted != 100;) {
            quicly_address_t dest, src;
            struct iovec datagrams[8];
            uint8_t buffer[8 * 1500];
            size_t count = 8;
            quicly_send_datagram_frames(client, &payload, 1);
            ok(quicly_send(client, &dest, &src, datagrams, &count, buffer, sizeof(buffer)) == 0);
            if (count == 0)
                break;
            emitted += count;
        }
        ok(emitted < 100 && ps->loss.sentmap.bytes_in_flight <= cwnd + ps->max_udp_payload_size);
        ok(client->egress.datagram_frame_payloads.count == 1);
        ok(quicly_ratemeter_is_cc_limited(&ps->ratemeter));
        if (ps->cc.type == &quicly_cc_type_cubic)
            ok(ps->cc.state.pico.cubic.cc_limited);
        /* ACK-only packets when send_window == 0 must not piggyback queued DATAGRAM frames */
        quicly_send_datagram_frames_path(client, 0, &payload, 1);
        ps->pn_space->unacked_count = 1;
        ps->pn_space->send_ack_at = quic_now;
        quicly_ranges_add(&ps->pn_space->ack_queue, 0, 1);
        uint64_t dgs_sent_before = client->super.stats.num_frames_sent.datagram;
        quicly_address_t ack_dst, ack_src;
        struct iovec ack_dg;
        uint8_t ack_buf[1500];
        size_t ack_cnt = 1;
        ok(quicly_send(client, &ack_dst, &ack_src, &ack_dg, &ack_cnt, ack_buf, sizeof(ack_buf)) == 0 && ack_cnt == 1);
        ok(client->super.stats.num_frames_sent.datagram == dgs_sent_before && quicly_get_num_datagram_frames_path(client, 0) == 1 &&
           client->egress.datagram_frame_payloads.count == 1);
        quicly_free(client);
        quicly_free(server);
    }

    /* path isolation for update_ratemeter */
    {
        quicly_context_t ctx = quic_ctx;
        ctx.egress[0].respect_app_limited = 1;
        ctx.egress[0].cc.initcwnd_packets = 2;
        ctx.egress[0].cc.normalize_mtu = 0;
        quicly_conn_t conn = {.super = {.ctx = &ctx, .remote = {.address_validation = {.validated = 1}}}, .stash = {.now = 1}};
        quicly_path_space_t ps = {0}, other = {0};
        struct st_quicly_conn_path_t path = {.validated = 1}, other_path = {.validated = 1};
        conn.path_spaces[0] = &ps;
        conn.path_spaces[1] = &other;
        ps.addrs[0] = &path;
        other.addrs[0] = &other_path;
        quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &ps.cc, &ctx.egress[0].cc, 1200, 1);
        quicly_ratemeter_init(&ps.ratemeter);
        ps.loss.sentmap.bytes_in_flight = ps.cc.cwnd;
        other.datagram_frame_payloads.count = 1;
        update_ratemeter(&conn, &ps, 0, 0, 0);
        ok(!ps.cc.state.pico.cubic.cc_limited);
        ps.datagram_frame_payloads.count = 1;
        update_ratemeter(&conn, &ps, 0, 0, 0);
        ok(ps.cc.state.pico.cubic.cc_limited);
        path.probe_only = 1;
        update_ratemeter(&conn, &ps, 0, 0, 0);
        ok(!ps.cc.state.pico.cubic.cc_limited);
        path.probe_only = 0;
        path.abandoned = 1;
        update_ratemeter(&conn, &ps, 0, 0, 0);
        ok(!ps.cc.state.pico.cubic.cc_limited);
    }

    /* backlogged CUBIC congestion-avoidance growth */
    quic_ctx.max_datagram_frame_payloads = 64;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_cubic_init;
    quicly_conn_t *client, *server;
    test_setup_connected_peers(&client, &server);
    quicly_cc_t *cc = &client->path_spaces[0]->cc;
    uint32_t initial = 2 * client->path_spaces[0]->max_udp_payload_size;
    cc->cwnd = cc->ssthresh = cc->state.pico.cubic.w_est = cc->state.pico.cubic.cwnd_prior = initial;
    cc->state.pico.cubic.epoch_start = 0;
    cc->state.pico.cubic.cc_limited = 0;
    for (size_t round = 0; round < 200; ++round) {
        for (size_t q = client->egress.datagram_frame_payloads.count; q < 64; ++q)
            quicly_send_datagram_frames(client, &payload, 1);
        transmit(client, server);
        quic_now += 20;
        transmit(server, client);
        quic_now += 20;
    }
    ok(cc->cwnd > initial * 2);
    quicly_free(client);
    quicly_free(server);

    quic_ctx = saved_ctx;
    quic_now = saved_now;
    subtest("path-zero-busy", do_test_multipath_cc_limited, 0);
    subtest("path-one-busy", do_test_multipath_cc_limited, 1);
}

static void zero_length_encrypt_cid(struct st_quicly_cid_encryptor_t *self, quicly_cid_t *encrypted, void *stateless_reset_token,
                                    const quicly_cid_plaintext_t *plaintext)
{
    (void)self;
    (void)plaintext;
    encrypted->len = 0;
    if (stateless_reset_token != NULL)
        memset(stateless_reset_token, 0, QUICLY_STATELESS_RESET_TOKEN_LEN);
}

static size_t zero_length_decrypt_cid(struct st_quicly_cid_encryptor_t *self, quicly_cid_plaintext_t *plaintext,
                                      const void *encrypted, size_t len)
{
    (void)self;
    (void)encrypted;
    if (len != 0)
        return SIZE_MAX;
    *plaintext = (quicly_cid_plaintext_t){0};
    return 0;
}

static int zero_length_generate_srt(struct st_quicly_cid_encryptor_t *self, void *token, const void *cid)
{
    (void)self;
    (void)cid;
    memset(token, 0, QUICLY_STATELESS_RESET_TOKEN_LEN);
    return 0;
}

static quicly_cid_encryptor_t zero_length_cid_encryptor = {zero_length_encrypt_cid, zero_length_decrypt_cid,
                                                           zero_length_generate_srt};

static ptls_iovec_t test_mp_ticket;

static int test_mp_encrypt_ticket_cb(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    int ret;
    (void)self;
    (void)tls;
    (void)is_encrypt;
    ptls_buffer_pushv(dst, src.base, src.len);
    ret = 0;
Exit:
    return ret;
}

static int test_mp_save_ticket_cb(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t input,
                                  const ptls_save_ticket_properties_t *props)
{
    (void)self;
    (void)tls;
    (void)props;
    free(test_mp_ticket.base);
    test_mp_ticket.base = malloc(input.len);
    assert(test_mp_ticket.base != NULL);
    memcpy(test_mp_ticket.base, input.base, input.len);
    test_mp_ticket.len = input.len;
    return 0;
}

static int backup_only_can_send_data(struct st_quicly_path_scheduler_t *sched, quicly_conn_t *conn, size_t path_index)
{
    (void)sched;
    return path_index == 1 && quicly_is_path_available(conn, path_index);
}

static void test_multipath_negotiation(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t saved = quic_ctx;

    /* unnegotiated multipath frames trigger PROTOCOL_VIOLATION */
    uint64_t bad_frames[] = {QUICLY_FRAME_TYPE_PATH_ABANDON, QUICLY_FRAME_TYPE_PATH_STATUS_AVAILABLE};
    for (size_t i = 0; i < PTLS_ELEMENTSOF(bad_frames); ++i) {
        quicly_conn_t *client, *server;
        quicly_context_t s = setup_multipath_regression_peers_limit(&client, &server, 0, 0);
        uint8_t fb[16], *p = fb;
        p = quicly_encodev(p, bad_frames[i]);
        p = quicly_encodev(p, 1);
        p = quicly_encodev(p, 0);
        ok(send_raw_1rtt_frame(client, server, 0, NULL, &fake_address.sa, fb, (size_t)(p - fb)) == 0);
        ok(quicly_get_state(server) == QUICLY_STATE_CLOSING);
        uint64_t ft;
        const char *reason;
        int is_remote;
        ok(quicly_get_close_reason(server, &ft, &reason, &is_remote) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
        free_multipath_regression_peers(client, server, s);
    }

    /* PATH_ACK checks local.max_path_id; remote CID validation; key-update delay & corrupt key-phase handling */
    {
        quicly_conn_t *client, *server;
        quicly_context_t s = setup_multipath_regression_peers(&client, &server, 0);
        uint8_t ack_fb[16], *p = ack_fb;
        p = quicly_encodev(p, 2);
        p = quicly_encodev(p, 0);
        p = quicly_encodev(p, 0);
        p = quicly_encodev(p, 0);
        p = quicly_encodev(p, 0);
        server->super.local.max_path_id = 1;
        struct st_quicly_handle_payload_state_t st = {.src = ack_fb, .end = p, .frame_type = QUICLY_FRAME_TYPE_PATH_ACK};
        ok(handle_path_ack_frame(server, &st) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
        server->super.local.max_path_id = 4;
        server->super.remote.max_path_id = 1;
        st.src = ack_fb;
        ok(handle_path_ack_frame(server, &st) == 0);

        uint8_t cid_len = client->path_spaces[0]->remote_cid_set.cids[0].cid.len;
        client->path_spaces[0]->remote_cid_set.cids[0].cid.len = 0;
        ok(apply_remote_transport_params(client) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
        client->path_spaces[0]->remote_cid_set.cids[0].cid.len = cid_len;

        /* key-update delay and forged flipped-key-phase packet rejection */
        uint64_t kp = client->application->cipher.egress.key_phase;
        client->application->cipher.egress.key_update_pn.next = client->application->cipher.egress.packets_sent;
        client->application->cipher.egress.key_update_pn.next_at = quic_now + 1;
        uint8_t ping = QUICLY_FRAME_TYPE_PING;
        ok(send_raw_1rtt_frame(client, server, 0, NULL, &fake_address.sa, &ping, 1) == 0);
        ok(client->application->cipher.egress.key_phase == kp);
        quic_now = client->application->cipher.egress.key_update_pn.next_at;
        ok(send_raw_1rtt_frame(client, server, 0, NULL, &fake_address.sa, &ping, 1) == 0);
        ok(client->application->cipher.egress.key_phase == kp + 1);

        uint8_t forged[64] = {0}, mask[5] = {0}, secret_before[PTLS_MAX_DIGEST_SIZE];
        const quicly_cid_t *dcid = get_dcid(client, 0);
        forged[0] = 0x40; /* opposite key phase from kp + 1 == 1 */
        memcpy(forged + 1, dcid->cid, dcid->len);
        for (size_t i = 1 + dcid->len; i < sizeof(forged); ++i)
            forged[i] = (uint8_t)(i * 37 + 11);
        ptls_cipher_init(client->application->cipher.egress.key.header_protection, forged + 1 + dcid->len + 4);
        ptls_cipher_encrypt(client->application->cipher.egress.key.header_protection, mask, mask, sizeof(mask));
        forged[0] ^= mask[0] & 0x1f;
        for (size_t i = 0; i < 4; ++i)
            forged[1 + dcid->len + i] ^= mask[1 + i];
        uint64_t prepared_before = server->application->cipher.ingress.key_phase.prepared;
        memcpy(secret_before, server->application->cipher.ingress.secret, sizeof(secret_before));
        struct iovec forged_iov = {.iov_base = forged, .iov_len = sizeof(forged)};
        quicly_decoded_packet_t dec;
        ok(decode_packets(&dec, &forged_iov, 1) == 1);
        ok(quicly_receive(server, NULL, &fake_address.sa, &dec) == QUICLY_ERROR_PACKET_IGNORED);
        ptls_aead_context_t *cached_next = server->application->cipher.ingress.next_aead;
        ok(cached_next != NULL);
        ok(server->application->cipher.ingress.key_phase.prepared == prepared_before);
        ok(memcmp(server->application->cipher.ingress.secret, secret_before, sizeof(secret_before)) == 0);
        /* second forged packet reuses cached candidate AEAD without re-deriving; valid packet then promotes it */
        ok(decode_packets(&dec, &forged_iov, 1) == 1);
        ok(quicly_receive(server, NULL, &fake_address.sa, &dec) == QUICLY_ERROR_PACKET_IGNORED);
        ok(server->application->cipher.ingress.next_aead == cached_next);
        client->application->cipher.egress.key_update_pn.next = client->application->cipher.egress.packets_sent;
        client->application->cipher.egress.key_update_pn.next_at = quic_now;
        ok(send_raw_1rtt_frame(client, server, 0, NULL, &fake_address.sa, &ping, 1) == 0);
        ok(server->application->cipher.ingress.next_aead == NULL &&
           server->application->cipher.ingress.key_phase.prepared == prepared_before + 1);
        free_multipath_regression_peers(client, server, s);
    }

    /* zero-length CID client suppresses multipath TP; server still rejects malformed 0-len CID + multipath TP; draft-29 fallback */
    {
        quicly_context_t c_ctx = quic_ctx, s_ctx = quic_ctx;
        c_ctx.transport_params.enable_multipath = s_ctx.transport_params.enable_multipath = 1;
        c_ctx.transport_params.initial_max_path_id = s_ctx.transport_params.initial_max_path_id = 4;
        quic_ctx.cid_encryptor = NULL;
        c_ctx.cid_encryptor = s_ctx.cid_encryptor = &zero_length_cid_encryptor;
        quicly_conn_t *client, *server;
        setup_asymmetric_peers(&client, &server, &c_ctx, &s_ctx, 1, 1);
        ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED && quicly_get_state(server) == QUICLY_STATE_CONNECTED);
        ok(!quicly_is_multipath(client) && !quicly_is_multipath(server) &&
           !server->super.remote.transport_params.enable_multipath && client->super.local.max_path_id == 0);
        /* server rejects a malformed peer ClientHello carrying both 0-length SCID and initial_max_path_id */
        quicly_cid_t empty_scid = {0};
        quicly_transport_parameters_t bad_tp = c_ctx.transport_params;
        ptls_buffer_t bad_tp_buf;
        ptls_buffer_init(&bad_tp_buf, "", 0);
        ok(quicly_encode_transport_parameter_list(&bad_tp_buf, &bad_tp, NULL, &empty_scid, NULL, NULL, 0) == 0);
        ptls_raw_extension_t slots[2] = {
            {get_transport_parameters_extension_id(server->super.version), {bad_tp_buf.base, bad_tp_buf.off}}, {UINT16_MAX}};
        ok(expand_handshake_result(server_collected_extensions(server->crypto.tls, &server->crypto.handshake_properties, slots)) ==
           QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
        ptls_buffer_dispose(&bad_tp_buf);
        quicly_free(client);
        quicly_free(server);
        quic_ctx = saved;

        quic_ctx.initial_version = QUICLY_PROTOCOL_VERSION_DRAFT29;
        quic_ctx.transport_params.enable_multipath = 1;
        quicly_context_t s = setup_multipath_regression_peers(&client, &server, 0);
        ok(!quicly_is_multipath(client) && !quicly_is_multipath(server));
        free_multipath_regression_peers(client, server, s);
        quic_ctx = saved;

        quicly_cid_encryptor_t *mp_enc = new_test_mp_encryptor();
        for (int mp_client = 0; mp_client < 2; ++mp_client) {
            c_ctx = quic_ctx;
            s_ctx = quic_ctx;
            quicly_context_t *mp = mp_client ? &c_ctx : &s_ctx;
            mp->cid_encryptor = mp_enc;
            mp->transport_params.enable_multipath = 1;
            mp->transport_params.initial_max_path_id = 4;
            setup_asymmetric_peers(&client, &server, &c_ctx, &s_ctx, mp_client, !mp_client);
            ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED && quicly_get_state(server) == QUICLY_STATE_CONNECTED);
            ok(!quicly_is_multipath(client) && !quicly_is_multipath(server));
            if (!mp_client)
                ok(!client->super.remote.transport_params.enable_multipath);
            ok(client->local_cid_path_map == NULL && server->local_cid_path_map == NULL);
            /* single-path fallback preserves negotiated mode across ctx edits and honors can_send_data during validation */
            c_ctx.transport_params.enable_multipath = 1;
            c_ctx.transport_params.initial_max_path_id = 4;
            ok(!quicly_is_multipath(client) && !quicly_is_multipath(server));
            quicly_path_scheduler_t deny_sched = quicly_default_path_scheduler;
            deny_sched.can_send_data = backup_only_can_send_data; /* returns 0 for path_index == 0 */
            quicly_context_t *orig_cctx = client->super.ctx, dctx = *orig_cctx;
            dctx.path_scheduler = &deny_sched;
            dctx.receive_datagram_frame = &receive_datagram_frame;
            client->super.ctx = &dctx;
            client->super.remote.transport_params.max_datagram_frame_size = 200;
            client->egress.pending_flows = 0;
            client->path_spaces[0]->pn_space->send_ack_at = INT64_MAX;
            client->path_spaces[0]->loss.alarm_at = INT64_MAX;
            quicly_stream_t *sp_stream;
            ok(quicly_open_stream(client, &sp_stream, 0) == 0 && quicly_streambuf_egress_write(sp_stream, "sp", 2) == 0);
            uint8_t sp_dg_bytes[8] = {0x11};
            ptls_iovec_t sp_dg = ptls_iovec_init(sp_dg_bytes, sizeof(sp_dg_bytes));
            quicly_send_datagram_frames(client, &sp_dg, 1);
            ok(quicly_get_first_timeout(client) > quic_now);
            quicly_address_t sp_dst, sp_src;
            struct iovec sp_iov;
            uint8_t sp_buf[1500];
            size_t sp_cnt = 1;
            ok(quicly_send(client, &sp_dst, &sp_src, &sp_iov, &sp_cnt, sp_buf, sizeof(sp_buf)) == 0 && sp_cnt == 0);
            /* due single-path PATH_RESPONSE sends without leaking STREAM or unbound DATAGRAM frames */
            lock_now(client, 1);
            get_path(client, 0)->path_response.send_ = 1;
            recalc_send_probe_at(client);
            unlock_now(client);
            ok(quicly_get_first_timeout(client) <= quic_now);
            sp_cnt = 1;
            uint64_t sp_streams_before = client->super.stats.num_frames_sent.stream;
            uint64_t sp_dgs_before = client->super.stats.num_frames_sent.datagram;
            ok(quicly_send(client, &sp_dst, &sp_src, &sp_iov, &sp_cnt, sp_buf, sizeof(sp_buf)) == 0 && sp_cnt == 1 &&
               client->super.stats.num_frames_sent.path_response == 1 &&
               client->super.stats.num_frames_sent.stream == sp_streams_before &&
               client->super.stats.num_frames_sent.datagram == sp_dgs_before && quicly_has_datagram_frames(client));
            client->super.ctx = orig_cctx;
            quicly_free(client);
            quicly_free(server);
        }
        /* server defers multipath frames until ClientFinished; 0-RTT budgets long-header DATAGRAMs and avoids flow-blocked spin */
        ptls_encrypt_ticket_t enc_ticket = {test_mp_encrypt_ticket_cb};
        ptls_save_ticket_t save_ticket = {test_mp_save_ticket_cb};
        ptls_context_t c_tls = *quic_ctx.tls, s_tls = *quic_ctx.tls;
        c_tls.save_ticket = &save_ticket;
        s_tls.encrypt_ticket = &enc_ticket;
        s_tls.ticket_lifetime = 86400;
        s_tls.max_early_data_size = UINT32_MAX;
        quic_ctx.cid_encryptor = mp_enc;
        c_ctx = quic_ctx;
        s_ctx = quic_ctx;
        c_ctx.tls = &c_tls;
        s_ctx.tls = &s_tls;
        c_ctx.transport_params.enable_multipath = s_ctx.transport_params.enable_multipath = 1;
        c_ctx.transport_params.initial_max_path_id = s_ctx.transport_params.initial_max_path_id = 3;
        c_ctx.transport_params.max_datagram_frame_size = s_ctx.transport_params.max_datagram_frame_size = 2000;
        c_ctx.receive_datagram_frame = s_ctx.receive_datagram_frame = &receive_datagram_frame;
        s_ctx.transport_params.max_streams_bidi = 1;
        s_ctx.transport_params.max_data = 16;

        quicly_address_t dst_a, src_a;
        struct iovec dgrams[8];
        uint8_t pbuf[PTLS_ELEMENTSOF(dgrams) * 1500];
        quicly_decoded_packet_t dec_pkts[PTLS_ELEMENTSOF(dgrams) * 4];
        size_t cnt = PTLS_ELEMENTSOF(dgrams);
        ok(quicly_connect(&client, &c_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                          NULL, NULL) == 0);
        ok(quicly_send(client, &dst_a, &src_a, dgrams, &cnt, pbuf, sizeof(pbuf)) == 0 && cnt == 1);
        ok(decode_packets(dec_pkts, dgrams, 1) == 1);
        ok(quicly_accept(&server, &s_ctx, NULL, &fake_address.sa, dec_pkts, NULL, new_master_id(), NULL, NULL) == 0);
        ok(!ptls_handshake_is_complete(quicly_get_tls(server)));
        ok(quicly_set_path_status(server, 0, 1) == 0);
        ok(transmit(server, client) > 0);
        /* server's 0.5-RTT flight must not emit multipath frames before ClientFinished */
        ok(!ptls_handshake_is_complete(quicly_get_tls(server)));
        ok(server->super.stats.num_frames_sent.path_new_connection_id == 0 && server->super.stats.num_frames_sent.path_status == 0);
        exchange_until_idle(client, server);
        ok(ptls_handshake_is_complete(quicly_get_tls(server)));
        ok(server->super.stats.num_frames_sent.path_new_connection_id > 0 && server->super.stats.num_frames_sent.path_status == 1);
        /* negotiated multipath connection preserves quicly_is_multipath even if shared ctx TPs are toggled afterward */
        c_ctx.transport_params.enable_multipath = 0;
        c_ctx.transport_params.initial_max_path_id = 0;
        ok(quicly_is_multipath(client));
        c_ctx.transport_params.enable_multipath = 1;
        c_ctx.transport_params.initial_max_path_id = 3;
        ptls_buffer_t rem_tp_buf;
        ptls_buffer_init(&rem_tp_buf, "", 0);
        ok(quicly_encode_transport_parameter_list(&rem_tp_buf, quicly_get_remote_transport_parameters(client), NULL, NULL, NULL,
                                                  NULL, 0) == 0);
        quicly_transport_parameters_t remembered_tp;
        ok(quicly_decode_transport_parameter_list(&remembered_tp, NULL, NULL, NULL, NULL, rem_tp_buf.base,
                                                  rem_tp_buf.base + rem_tp_buf.off) == 0);
        ptls_buffer_dispose(&rem_tp_buf);
        ok(remembered_tp.max_datagram_frame_size == 2000 && !remembered_tp.enable_multipath);
        quicly_free(client);
        quicly_free(server);
        ok(test_mp_ticket.len > 0);

        /* resumed 0-RTT client: public resumption API applies max_datagram_frame_size + budgets long-header DATAGRAMs */
        ptls_handshake_properties_t hs_props = {.client = {.session_ticket = test_mp_ticket}};
        ok(quicly_connect(&client, &c_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                          &hs_props, &remembered_tp, NULL) == 0);
        ok(client->application != NULL && !client->application->one_rtt_writable &&
           client->application->cipher.egress.key.aead != NULL &&
           quicly_get_remote_transport_parameters(client)->max_datagram_frame_size == 2000);
        uint8_t over_0rtt_bytes[1242] = {0}, fit_0rtt_bytes[1200] = {0};
        ptls_iovec_t zrtt_dgs[2] = {ptls_iovec_init(over_0rtt_bytes, sizeof(over_0rtt_bytes)),
                                    ptls_iovec_init(fit_0rtt_bytes, sizeof(fit_0rtt_bytes))};
        quicly_send_datagram_frames(client, zrtt_dgs, 2);
        quicly_stream_t *s0, *s1;
        ok(quicly_open_stream(client, &s0, 0) == 0 &&
           quicly_streambuf_egress_write(s0, "0123456789abcdef0123456789abcdef", 32) == 0);
        ok(quicly_open_stream(client, &s1, 0) == 0);
        cnt = PTLS_ELEMENTSOF(dgrams);
        ok(quicly_send(client, &dst_a, &src_a, dgrams, &cnt, pbuf, sizeof(pbuf)) == 0 && cnt >= 2);
        ok(client->super.stats.num_packets.zero_rtt_sent > 0 && client->super.stats.num_frames_sent.datagram == 1 &&
           client->super.stats.num_frames_sent.data_blocked == 1 && client->super.stats.num_frames_sent.streams_blocked == 1);
        ok(quicly_get_first_timeout(client) > quic_now);
        size_t spin_cnt = PTLS_ELEMENTSOF(dgrams);
        ok(quicly_send(client, &dst_a, &src_a, dgrams, &spin_cnt, pbuf, sizeof(pbuf)) == 0 && spin_cnt == 0);

        size_t num_dec = decode_packets(dec_pkts, dgrams, cnt);
        ok(num_dec >= 2);
        ok(quicly_accept(&server, &s_ctx, NULL, &fake_address.sa, &dec_pkts[0], NULL, new_master_id(), NULL, NULL) == 0);
        for (size_t k = 1; k < num_dec; ++k)
            ok(quicly_receive(server, NULL, &fake_address.sa, &dec_pkts[k]) == 0);
        ok(transmit(server, client) > 0);
        /* 0.5-RTT server acknowledges 0-RTT with standard ACK rather than PATH_ACK until ClientFinished */
        ok(server->super.stats.num_frames_sent.path_ack == 0 && server->super.stats.num_frames_sent.path_new_connection_id == 0);
        exchange_until_idle(client, server);
        ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED && quicly_get_state(server) == QUICLY_STATE_CONNECTED);
        quicly_free(client);
        quicly_free(server);
        free(test_mp_ticket.base);
        test_mp_ticket = ptls_iovec_init(NULL, 0);
        quicly_free_default_cid_encryptor(mp_enc);
        quic_ctx.cid_encryptor = saved.cid_encryptor;
    }

    quic_ctx = saved;
    quic_now = saved_now;
}

static void rate_test_ack(quicly_conn_t *conn, size_t path_index, uint16_t bytes)
{
    quicly_path_space_t *ps = conn->path_spaces[path_index];
    uint64_t pn = ps->packet_number++;
    ok(quicly_sentmap_prepare(&ps->loss.sentmap, pn, quic_now - 1, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&ps->loss.sentmap, bytes, 0);
    ps->last_retransmittable_sent_at = quic_now - 1;
    quicly_ack_frame_t ack = {.largest_acknowledged = pn, .smallest_acknowledged = pn, .ack_block_lengths = {1}};
    struct st_quicly_handle_payload_state_t state = {.epoch = QUICLY_EPOCH_1RTT};
    lock_now(conn, 0);
    ok(process_ack_frame_core(conn, &state, ps->path_id, &ack) == 0);
    ok(process_ack_frame_core(conn, &state, ps->path_id, &ack) == 0);
    unlock_now(conn);
}

static void test_multipath_state_isolation(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t orig = quic_ctx;
    quic_ctx.egress[0].ecn = QUICLY_ECN_MODE_L4S;
    quicly_conn_t *client, *server;
    quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);

    /* anti-amplification on path 0 including pre_validation_amplification_limit == 0 */
    server->super.remote.address_validation.validated = 0;
    get_path(server, 0)->bytes_received = 100;
    get_path(server, 0)->bytes_sent = 250;
    ok(calc_amplification_limit_allowance(server, get_path(server, 0)) == 50);
    quic_ctx.pre_validation_amplification_limit = 0;
    ok(calc_amplification_limit_allowance(server, get_path(server, 0)) == 0);
    quic_ctx.pre_validation_amplification_limit = orig.pre_validation_amplification_limit;
    server->super.remote.address_validation.validated = 1;
    get_path(server, 0)->bytes_received = get_path(server, 0)->bytes_sent = 0;

    /* CID starvation schedules PATH_CIDS_BLOCKED(0); out-of-order CID seq 1 selects seq 1 and reports next seq 2 */
    struct sockaddr_in remote = loopback_addr(12345), local = loopback_addr(54321);
    for (size_t p = 1; p < PTLS_ELEMENTSOF(client->path_spaces); ++p)
        if (client->path_spaces[p] != NULL) {
            client->path_spaces[p]->next_expected_cid_seq = 0;
            for (size_t c = 0; c < PTLS_ELEMENTSOF(client->path_spaces[p]->remote_cid_set.cids); ++c) {
                client->path_spaces[p]->remote_cid_set.cids[c].state = QUICLY_REMOTE_CID_UNAVAILABLE;
                client->path_spaces[p]->remote_cid_set.cids[c].cid.len = 0;
            }
        }
    ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == QUICLY_ERROR_PACKET_IGNORED);
    ok(client->path_spaces[1]->path_cids_blocked.sender == QUICLY_SENDER_STATE_SEND);
    ok(client->path_spaces[1]->path_cids_blocked.sequence == 0);

    uint8_t cid_bytes[8] = {9, 9, 9, 9, 9, 9, 9, 1}, srt_bytes[16] = {1};
    quicly_new_connection_id_frame_t ncid1 = {
        .sequence = 1, .retire_prior_to = 0, .cid = ptls_iovec_init(cid_bytes, 8), .stateless_reset_token = srt_bytes};
    ok(register_remote_cid(client, client->path_spaces[3], &ncid1) == 0);
    lock_now(client, 0);
    ok(new_path(client, 3, client->path_spaces[3]->path_id, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    ok(setup_path_dcid(client, 3) && get_path(client, 3)->dcid == 1 && get_dcid(client, 3)->len == 8);
    schedule_path_cids_blocked(client, client->path_spaces[3]);
    ok(client->path_spaces[3]->path_cids_blocked.sequence == 2);
    destroy_path_state(client, 3);
    unlock_now(client);

    /* PATH_STATUS sequence monotonicity, CC switch inheritance, and overdue loss isolation */
    uint8_t sb[16], *se;
    uint64_t seqs[] = {5, 4, 6}, types[] = {QUICLY_FRAME_TYPE_PATH_STATUS_BACKUP, QUICLY_FRAME_TYPE_PATH_STATUS_AVAILABLE,
                                            QUICLY_FRAME_TYPE_PATH_STATUS_AVAILABLE};
    int expected_backup[] = {1, 1, 0};
    ok(new_path(client, 1, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    for (size_t i = 0; i < 3; ++i) {
        se = sb;
        se = quicly_encodev(se, 1);
        se = quicly_encodev(se, seqs[i]);
        struct st_quicly_handle_payload_state_t st = {.src = sb, .end = se, .frame_type = types[i]};
        ok(handle_path_status_frame(client, &st) == 0 && client->path_spaces[1]->is_backup == expected_backup[i]);
    }
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) && client->path_spaces[1]->cc.type == &quicly_cc_type_cubic);

    quicly_path_space_t *other = client->path_spaces[1];
    ok(quicly_sentmap_prepare(&other->loss.sentmap, 0, quic_now - 1000, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&other->loss.sentmap, 1200, 0);
    other->packet_number = 2;
    other->last_retransmittable_sent_at = quic_now - 1000;
    other->loss.largest_acked_packet_plus1.per_epoch[QUICLY_EPOCH_1RTT] = other->loss.largest_acked_packet_plus1.all_ = 2;
    other->loss.loss_time = other->loss.alarm_at = quic_now - 1;
    uint64_t losses_before = client->super.stats.num_packets.lost, pn0 = client->path_spaces[0]->packet_number++;
    ok(quicly_sentmap_prepare(&client->path_spaces[0]->loss.sentmap, pn0, quic_now, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&client->path_spaces[0]->loss.sentmap, 0, 0);
    quicly_ack_frame_t ack = {.largest_acknowledged = pn0, .smallest_acknowledged = pn0, .ack_block_lengths = {1}};
    struct st_quicly_handle_payload_state_t ack_st = {.epoch = QUICLY_EPOCH_1RTT};
    lock_now(client, 0);
    ok(process_ack_frame_core(client, &ack_st, 0, &ack) == 0);
    ok(client->super.stats.num_packets.lost == losses_before && other->loss.sentmap.bytes_in_flight == 1200);
    size_t min_pkts;
    int restrict_send;
    ok(quicly_loss_on_alarm(&other->loss, quic_now, client->super.remote.transport_params.max_ack_delay, 1, &min_pkts,
                            &restrict_send, on_loss_detected) == 0);
    ok(client->super.stats.num_packets.lost == losses_before + 1 && other->loss.sentmap.bytes_in_flight == 0);
    unlock_now(client);
    free_multipath_regression_peers(client, server, saved);

    /* per-path ECN probing/isolation, distinct secondary egress AEAD, and delivery rate across rebinding */
    saved = setup_multipath_regression_peers(&client, &server, 0);
    quic_now += 5000;
    open_multipath_test_path(client);
    ok(client->path_spaces[1]->ecn.state == QUICLY_ECN_PROBING && client->path_spaces[1]->ecn.probing_started_at == INT64_MAX);
    multipath_run(client, server, 20, -1, -1);
    ok(client->path_spaces[1]->ecn.probing_started_at >= 5000 && client->path_spaces[1]->egress_aead != NULL);
    ok(client->path_spaces[1]->egress_aead != client->application->cipher.egress.key.aead);
    client->path_spaces[0]->ecn.state = client->egress.ecn.state = QUICLY_ECN_PROBING;
    client->path_spaces[0]->packet_number = client->path_spaces[1]->packet_number = 50;
    quicly_ack_frame_t ack0 = {.largest_acknowledged = 40, .ecn_counts = {0, 40, 0}}, ack1 = {.largest_acknowledged = 40};
    quicly_cc_ecn_counts_t counts;
    handle_ecn_feedback(client, client->path_spaces[0], QUICLY_EPOCH_1RTT, &ack0, 1, &counts);
    client->path_spaces[1]->ecn.state = QUICLY_ECN_PROBING;
    handle_ecn_feedback(client, client->path_spaces[1], QUICLY_EPOCH_1RTT, &ack1, 0, &counts);
    ok(client->path_spaces[0]->ecn.state == QUICLY_ECN_ON && client->path_spaces[1]->ecn.state == QUICLY_ECN_OFF);

    ptls_iovec_t backlog = ptls_iovec_init("queued", 6);
    for (size_t p = 0; p != 2; ++p) {
        quicly_send_datagram_frames_path(client, p, &backlog, 1);
        quicly_ratemeter_init(&client->path_spaces[p]->ratemeter);
        quicly_ratemeter_enter_cc_limited(&client->path_spaces[p]->ratemeter, client->path_spaces[p]->packet_number);
    }
    uint64_t p1_acked_before = client->path_spaces[1]->num_packets.bytes_acked;
    rate_test_ack(client, 0, 1000);
    rate_test_ack(client, 1, 200);
    size_t cand = encode_flat_path_index(1, 1);
    remote = loopback_addr(12346);
    lock_now(client, 0);
    ok(new_path(client, cand, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
    get_path(client, cand)->probe_only = 0;
    quicly_send_datagram_frames_path(client, cand, &backlog, 1);
    ok(promote_path(client, cand) == 0 && client->path_spaces[1]->num_packets.bytes_acked == p1_acked_before + 200);
    unlock_now(client);
    for (size_t p = 0; p != 2; ++p)
        if (!quicly_ratemeter_is_cc_limited(&client->path_spaces[p]->ratemeter))
            quicly_ratemeter_enter_cc_limited(&client->path_spaces[p]->ratemeter, client->path_spaces[p]->packet_number);
    for (int step = 0; step < 5; ++step) {
        quic_now += 10;
        rate_test_ack(client, 1, 200);
        rate_test_ack(client, 0, 1000);
    }
    quicly_rate_t r0, r1;
    quicly_ratemeter_report(&client->path_spaces[0]->ratemeter, &r0);
    quicly_ratemeter_report(&client->path_spaces[1]->ratemeter, &r1);
    ok(r0.latest == 100000 && r1.latest == 20000);
    free_multipath_regression_peers(client, server, saved);

    /* alt-egress policy inheritance, fractional PATH_ACK RTT, and unused-space close timeout */
    quic_ctx = orig;
    quic_ctx.alt_egress_ratio[0] = 255;
    quic_ctx.egress[1] = orig.egress[0];
    quic_ctx.egress[1].cc.init_cc = &quicly_cc_cubic_init;
    quic_ctx.egress[1].cc.initcwnd_packets = 14;
    quic_ctx.egress[1].pacing = 1;
    quic_now = INT64_C(1800000000000);
    saved = setup_multipath_regression_peers(&client, &server, 0);
    ok(quicly_get_alt_egress(client) == 1 && client->path_spaces[0]->cc.conf == &quic_ctx.egress[1].cc);
    quic_now_submillisec = 0.125;
    lock_now(client, 0);
    if (client->path_spaces[1] != NULL) {
        free_path_space(client->path_spaces[1]);
        client->path_spaces[1] = NULL;
    }
    ok(new_path(client, 1, 1, &fake_address.sa, &fake_address.sa) == 0);
    quicly_path_space_t *ps1 = client->path_spaces[1];
    ok(ps1->cc.conf == &quic_ctx.egress[1].cc && ps1->pacer != NULL && ps1->pacer != client->path_spaces[0]->pacer);
    uint64_t pn1 = ps1->packet_number++;
    ok(quicly_sentmap_prepare(&ps1->loss.sentmap, pn1, client->stash.now_double, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&ps1->loss.sentmap, 1200, 0);
    ps1->last_retransmittable_sent_at = client->stash.now_double;
    unlock_now(client);
    quic_now_submillisec = 0.75;
    quicly_ack_frame_t fack = {.largest_acknowledged = pn1, .smallest_acknowledged = pn1, .ack_block_lengths = {1}};
    lock_now(client, 0);
    ok(process_ack_frame_core(client, &ack_st, ps1->path_id, &fack) == 0 && ps1->loss.rtt.latest == 0.625f);
    unlock_now(client);
    for (size_t i = 2; i < PTLS_ELEMENTSOF(client->path_spaces); ++i)
        if (client->path_spaces[i] != NULL)
            client->path_spaces[i]->loss.rtt.smoothed = 1000;
    destroy_path_state(client, 1);
    double primary_exp =
        quicly_loss_get_sentmap_expiration_time(&client->path_spaces[0]->loss, client->super.remote.transport_params.max_ack_delay);
    ok(get_max_sentmap_expiration_time(client) == primary_exp);
    ok(quicly_close(client, 0, "unused spaces") == 0);
    int64_t expires_at = ceil(quic_now + quic_now_submillisec + primary_exp);
    quic_now_submillisec = 0;
    quicly_address_t dest, src;
    struct iovec dgram;
    uint8_t buf[1500];
    size_t cnt = 1;
    ok(quicly_send(client, &dest, &src, &dgram, &cnt, buf, sizeof(buf)) == 0 && cnt == 1);
    ok(quicly_get_first_timeout(client) == expires_at);
    quic_now = expires_at;
    cnt = 1;
    ok(quicly_send(client, &dest, &src, &dgram, &cnt, buf, sizeof(buf)) == QUICLY_ERROR_FREE_CONNECTION);
    free_multipath_regression_peers(client, server, saved);

    quic_ctx = orig;
    quic_now = saved_now;
}

static void abandon_update_packet(quicly_sentmap_t *map, uint64_t pn, quicly_sentmap_event_t event)
{
    quicly_sentmap_iter_t iter;
    quicly_sentmap_init_iter(map, &iter);
    const quicly_sent_packet_t *packet;
    while ((packet = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX) {
        if (packet->packet_number == pn) {
            ok(quicly_sentmap_update(map, &iter, event) == 0);
            return;
        }
        quicly_sentmap_skip(&iter);
    }
    ok(!"packet missing from sentmap");
}

static void test_multipath_lifecycle(void)
{
    int64_t orig_now = quic_now;
    quicly_context_t orig = quic_ctx;

    /* path status, path 0 abandon with delayed stream + PATH_ACK + 3-PTO expiry, and ACK_FREQUENCY across abandon */
    {
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
        quic_ctx.ack_frequency = 1024;
        open_multipath_test_path(client);
        multipath_run(client, server, 25, -1, -1);
        ok(quicly_set_path_status(client, 1, 1) == 0 && client->path_spaces[1]->path_status.sequence == 0);
        ok(quicly_set_path_status(client, 1, 1) == 0 && client->path_spaces[1]->path_status.sequence == 0);
        ok(quicly_set_path_status(client, 1, 0) == 0 && client->path_spaces[1]->path_status.sequence == 1);

        client->path_spaces[0]->cc.num_loss_episodes = client->path_spaces[1]->cc.num_loss_episodes =
            QUICLY_FIRST_ACK_FREQUENCY_LOSS_EPISODE;
        client->path_spaces[0]->cc.cwnd = 9 * client->path_spaces[0]->max_udp_payload_size;
        client->path_spaces[1]->cc.cwnd = 6 * client->path_spaces[1]->max_udp_payload_size;
        client->egress.ack_frequency.update_at = 0;
        quicly_stream_t *af_stream;
        ok(quicly_open_stream(client, &af_stream, 0) == 0);
        ok(quicly_streambuf_egress_write(af_stream, "probe", 5) == 0);
        multipath_run(client, server, 10, -1, -1);
        ok(server->path_spaces[0]->pn_space->packet_tolerance == 6 && server->path_spaces[1]->pn_space->packet_tolerance == 6);

        /* hold back server stream packet on path 0 until after client abandons path 0 */
        quicly_stream_t *s_stream;
        ok(quicly_open_stream(server, &s_stream, 0) == 0);
        ok(quicly_streambuf_egress_write(s_stream, "delayed stream", 14) == 0);
        quicly_send_context_t sc;
        struct iovec delayed_dg;
        uint8_t delayed_buf[1500];
        test_setup_send_context(server, &sc, &delayed_dg, delayed_buf, sizeof(delayed_buf));
        ok(quicly_send_stream(s_stream, &sc) == 0 && commit_send_packet(server, &sc, 0) == 0);
        update_send_alarm(server, scheduler_can_send(server), server->path_spaces[0]);
        unlock_now(server);

        ok(quicly_abandon_path(client, 0, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
        quicly_decoded_packet_t dec;
        ok(decode_packets(&dec, &delayed_dg, 1) == 1 && quicly_receive(client, NULL, &fake_address.sa, &dec) == 0);
        ok(multipath_received_length(client, s_stream->stream_id) == 14 && client->path_spaces[0]->pn_space->send_ack_at == 0);
        transmit_multipath(client, server);
        ok(s_stream->sendstate.acked.ranges[0].end == 14);

        uint64_t srv_max_pid_before = server->super.local.max_path_id;
        quicly_loss_t *loss0 = &client->path_spaces[0]->loss;
        double pto0 = quicly_rtt_get_pto(&loss0->rtt, client->super.remote.transport_params.max_ack_delay, loss0->conf->min_pto);
        /* local abandon stays retained past 3 PTOs until reciprocal PATH_ABANDON arrives, then expires 3 PTOs after receipt */
        quic_now = ceil(get_path(client, 0)->abandoned_at + 4 * pto0);
        multipath_run(client, server, 5, -1, -1);
        ok(client->path_spaces[0]->peer_abandon_received && get_path(client, 0)->abandoned_at != INT64_MAX);
        pto0 = quicly_rtt_get_pto(&loss0->rtt, client->super.remote.transport_params.max_ack_delay, loss0->conf->min_pto);
        quicly_loss_t *srv_loss0 = &server->path_spaces[0]->loss;
        double srv_pto0 =
            quicly_rtt_get_pto(&srv_loss0->rtt, server->super.remote.transport_params.max_ack_delay, srv_loss0->conf->min_pto);
        int64_t exp_at = ceil(get_path(client, 0)->abandoned_at + 3 * pto0);
        int64_t srv_exp_at = ceil(get_path(server, 0)->abandoned_at + 3 * srv_pto0);
        quic_now = exp_at > srv_exp_at ? exp_at : srv_exp_at;
        multipath_run(client, server, 5, -1, -1);
        ok(get_path(client, 0)->abandoned_at == INT64_MAX && get_path(server, 0)->abandoned &&
           server->super.local.max_path_id == srv_max_pid_before + 1);

        client->path_spaces[1]->cc.cwnd = 8 * client->path_spaces[1]->max_udp_payload_size;
        client->egress.ack_frequency.update_at = 0;
        ok(quicly_streambuf_egress_write(af_stream, "probe", 5) == 0);
        multipath_run(client, server, 10, -1, -1);
        ok(server->path_spaces[1]->pn_space->packet_tolerance == 8);
        free_multipath_regression_peers(client, server, saved);
    }

    /* abandoned-path CID ignore, unopened-path abandon status/PN preservation, and PATH_ABANDON on candidate tuple */
    {
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
        open_multipath_test_path(client);
        multipath_run(client, server, 25, -1, -1);

        /* PATH_ABANDON received on a candidate address must keep the candidate alive during do_receive without promoting it */
        size_t srv_cand = encode_flat_path_index(1, 1);
        struct sockaddr_in cand_peer = loopback_addr(20055);
        lock_now(server, 0);
        ok(new_path(server, srv_cand, 1, (struct sockaddr *)&cand_peer, &fake_address.sa) == 0);
        get_path(server, srv_cand)->validated = 1;
        unlock_now(server);
        uint8_t ab_frame[16], *ab_p = quicly_encode_path_abandon_frame(ab_frame, 1, QUICLY_PATH_ABANDON_ERROR_APPLICATION);
        ok(send_raw_1rtt_frame(client, server, 1, &fake_address.sa, (struct sockaddr *)&cand_peer, ab_frame,
                               (size_t)(ab_p - ab_frame)) == 0);
        ok(get_path(server, 1)->abandoned && get_path(server, srv_cand) != NULL && get_path(server, srv_cand)->abandoned);
        ok(server->path_spaces[1]->pn_space->send_ack_at == 0);

        /* reordered CIDs on abandoned path 1 ignored before and after retention expiry */
        ok(quicly_abandon_path(client, 1, 0) == 0);
        uint8_t reset[40];
        memset(reset, 0xcd, sizeof(reset));
        quicly_decoded_packet_t reset_pkt = {.octets = ptls_iovec_init(reset, sizeof(reset))};
        deliver_multipath_cid(server, client, 0, 1, 4, 0, reset + 24);
        ok(!is_stateless_reset(client, &reset_pkt));
        lock_now(client, 0);
        ok(expire_abandoned_path_state(client, 1) == 0);
        unlock_now(client);
        deliver_multipath_cid(server, client, 0, 1, 4, 0, reset + 24);
        ok(!is_stateless_reset(client, &reset_pkt) && find_path_space_by_id(client, 1) == NULL);

        /* unopened path 2 abandoned by peer cancels queued local PATH_STATUS and preserves next_expected_packet_number */
        ok(quicly_set_path_status(client, 2, 1) == 0);
        uint64_t expected_pn = client->path_spaces[2]->pn_space->next_expected_packet_number;
        ab_p = quicly_encode_path_abandon_frame(ab_frame, 2, QUICLY_PATH_ABANDON_ERROR_APPLICATION);
        ok(send_raw_1rtt_frame(server, client, 0, NULL, &fake_address.sa, ab_frame, (size_t)(ab_p - ab_frame)) == 0);
        ok(path_id_is_abandoned(client, 2) && client->path_spaces[2]->path_status.sender == QUICLY_SENDER_STATE_NONE);
        quicly_send_context_t s;
        struct iovec raw;
        uint8_t pktbuf[1500];
        test_setup_send_context(server, &s, &raw, pktbuf, sizeof(pktbuf));
        s.dcid = &server->path_spaces[2]->remote_cid_set.cids[0].cid;
        ok(do_allocate_frame(server, &s, 1, ALLOCATE_FRAME_TYPE_ACK_ELICITING) == 0);
        *s.dst++ = QUICLY_FRAME_TYPE_PING;
        uint32_t saved_pid = get_path(server, 0)->path_id;
        get_path(server, 0)->path_id = 2;
        ok(commit_send_packet(server, &s, 0) == 0);
        get_path(server, 0)->path_id = saved_pid;
        unlock_now(server);
        quicly_decoded_packet_t dec;
        ok(decode_packets(&dec, &raw, 1) == 1);
        ok(quicly_receive(client, &fake_address.sa, (struct sockaddr *)&cand_peer, &dec) == QUICLY_ERROR_PACKET_IGNORED);
        ok(client->path_spaces[2]->pn_space->next_expected_packet_number == expected_pn);
        free_multipath_regression_peers(client, server, saved);
    }

    /* retired_path_abandon loss, retransmit, and late ACK after slot reuse */
    {
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
        open_multipath_test_path(client);
        multipath_run(client, server, 25, -1, -1);
        ok(quicly_abandon_path(client, 1, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
        uint64_t first_pn = client->path_spaces[0]->packet_number;
        quicly_address_t dst, src;
        struct iovec dgram;
        uint8_t buf[1500];
        size_t cnt = 1;
        ok(quicly_send(client, &dst, &src, &dgram, &cnt, buf, sizeof(buf)) == 0 && cnt == 1);
        lock_now(client, 0);
        ok(expire_abandoned_path_state(client, 1) == 0 && client->path_spaces[1] == NULL);
        unlock_now(client);
        ok(client->retired_path_abandon != NULL && client->retired_path_abandon->sender == QUICLY_SENDER_STATE_UNACKED);
        quicly_sentmap_t *map = &client->path_spaces[0]->loss.sentmap;
        abandon_update_packet(map, first_pn, QUICLY_SENTMAP_EVENT_LOST);
        ok(client->retired_path_abandon->sender == QUICLY_SENDER_STATE_SEND);
        uint64_t retry_pn = client->path_spaces[0]->packet_number;
        cnt = 1;
        ok(quicly_send(client, &dst, &src, &dgram, &cnt, buf, sizeof(buf)) == 0 && cnt == 1);
        lock_now(client, 0);
        ok(new_path(client, 2, 2, &fake_address.sa, &fake_address.sa) == 0);
        unlock_now(client);
        ok(quicly_abandon_path(client, 2, QUICLY_PATH_ABANDON_ERROR_UNSTABLE_OR_POOR) == 0);
        lock_now(client, 0);
        ok(expire_abandoned_path_state(client, 2) == 0 && alloc_path_space(client, 1, 5) == 0);
        unlock_now(client);
        abandon_update_packet(map, first_pn, QUICLY_SENTMAP_EVENT_ACKED);
        ok(client->retired_path_abandon->path_id == 2 && client->retired_path_abandon->next == NULL);
        abandon_update_packet(map, retry_pn, QUICLY_SENTMAP_EVENT_LOST);
        abandon_update_packet(map, retry_pn, QUICLY_SENTMAP_EVENT_ACKED);
        ok(client->path_spaces[1]->path_id == 5 && client->retired_path_abandon->path_id == 2);
        free_multipath_regression_peers(client, server, saved);
    }

    /* resource-limit rejection (including asymmetric remote.max_path_id deferral) and runtime active_connection_id_limit */
    {
        quic_ctx.cid_encryptor = new_test_mp_encryptor();
        quicly_context_t c_ctx = quic_ctx, s_ctx = quic_ctx;
        c_ctx.transport_params.initial_max_path_id = 2;
        s_ctx.transport_params.initial_max_path_id = QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT;
        quicly_conn_t *client, *server;
        setup_asymmetric_peers(&client, &server, &c_ctx, &s_ctx, 1, 1);
        /* fill server's remaining secondary slots, then client sends CID for next path while client's max_path_id is 2 */
        uint8_t token[16] = {0};
        for (uint32_t pid = 3; pid <= QUICLY_MAX_PATH_SPACES; ++pid)
            deliver_multipath_cid(client, server, 0, pid, 0, 0, token);
        ok(server->retired_path_abandon != NULL && server->retired_path_abandon->path_id == QUICLY_MAX_PATH_SPACES);
        multipath_run(client, server, 10, -1, -1);
        /* server must not emit deferred PATH_ABANDON while server->remote.max_path_id == 2; client stays connected */
        ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED && server->retired_path_abandon != NULL);
        /* once client raises MAX_PATH_ID, server emits the deferred resource-limit PATH_ABANDON */
        client->super.local.max_path_id = QUICLY_MAX_PATH_SPACES;
        client->egress.max_path_id = QUICLY_SENDER_STATE_SEND;
        client->egress.pending_flows |= QUICLY_PENDING_FLOW_OTHERS_BIT;
        multipath_run(client, server, 20, -1, -1);
        ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED && server->retired_path_abandon == NULL);
        ok(path_id_is_abandoned(client, QUICLY_MAX_PATH_SPACES));
        deliver_multipath_cid(client, server, 0, QUICLY_MAX_PATH_SPACES + 1, 0, 0, token);
        ok(quicly_get_state(server) == QUICLY_STATE_CLOSING);
        free_multipath_regression_peers(client, server, orig);

        quic_ctx.transport_params.active_connection_id_limit = 2;
        quicly_context_t mp_saved = setup_multipath_regression_peers_limit(&client, &server, 0, 1);
        ok(client->super.remote.transport_params.active_connection_id_limit == 2);
        schedule_path_cids_blocked(client, client->path_spaces[1]);
        ok(client->path_spaces[1]->path_cids_blocked.sequence == 1);
        deliver_multipath_cid(server, client, 0, 0, 2, 1, token);
        ok(quicly_get_state(client) == QUICLY_STATE_CLOSING);
        free_multipath_regression_peers(client, server, mp_saved);
        quic_ctx = orig;
    }

    /* dynamic MAX_PATH_ID, never-bound secondary abandon replenishment, 1200-MTU clamp, disable_migration, NO_VIABLE_PATH */
    {
        quic_ctx.cid_encryptor = new_test_mp_encryptor();
        quicly_context_t c_ctx = quic_ctx, s_ctx = quic_ctx;
        c_ctx.transport_params.enable_multipath = s_ctx.transport_params.enable_multipath = 1;
        c_ctx.transport_params.initial_max_path_id = 4;
        s_ctx.transport_params.initial_max_path_id = 0;
        s_ctx.transport_params.max_udp_payload_size = 1200;
        quicly_conn_t *client, *server;
        setup_asymmetric_peers(&client, &server, &c_ctx, &s_ctx, 1, 1);
        struct sockaddr_in remote = loopback_addr(10000), local = loopback_addr(20000);
        ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == QUICLY_ERROR_PACKET_IGNORED);
        ok(client->egress.paths_blocked.sender == QUICLY_SENDER_STATE_SEND);
        multipath_run(client, server, 10, -1, -1);

        server->super.local.max_path_id = 1;
        provision_multipath_cids(server);
        server->egress.max_path_id = QUICLY_SENDER_STATE_SEND;
        server->egress.pending_flows |= QUICLY_PENDING_FLOW_OTHERS_BIT;
        multipath_run(client, server, 20, -1, -1);
        ok(client->super.remote.max_path_id == 1);

        /* abandon path 1 before sending any packet on it; server replenishes credit so replacement path 2 opens */
        ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
        ok(client->path_spaces[1]->max_udp_payload_size == 1200);
        ok(quicly_abandon_path(client, 1, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
        multipath_run(client, server, 25, -1, -1);
        quic_now += 2000;
        multipath_run(client, server, 25, -1, -1);
        ok(client->super.remote.max_path_id >= 2);
        local = loopback_addr(20100);
        ok(quicly_open_path(client, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
        quicly_address_t dst_a, src_a;
        struct iovec out_dg;
        uint8_t out_buf[1500];
        size_t out_cnt = 1;
        ok(quicly_send(client, &dst_a, &src_a, &out_dg, &out_cnt, out_buf, sizeof(out_buf)) == 0 && out_cnt == 1);
        ok(out_dg.iov_len <= 1200);
        quicly_decoded_packet_t dec;
        ok(decode_packets(&dec, &out_dg, 1) == 1 && quicly_receive(server, &dst_a.sa, &src_a.sa, &dec) == 0);
        multipath_run(client, server, 25, -1, -1);
        size_t repl = client->path_spaces[1] != NULL ? 1 : 2;
        ok(quicly_is_path_available(client, repl));

        /* abandon path 0, then peer abandons last viable path -> local CLOSING with NO_VIABLE_PATH */
        ok(quicly_abandon_path(client, 0, QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
        multipath_run(client, server, 10, -1, -1);
        server->path_spaces[1]->path_abandon.sender = QUICLY_SENDER_STATE_SEND;
        server->path_spaces[1]->path_abandon.error_code = 0;
        server->egress.pending_flows |= QUICLY_PENDING_FLOW_OTHERS_BIT;
        ok(transmit_multipath(server, client) > 0 && quicly_get_state(client) == QUICLY_STATE_CLOSING);
        uint64_t close_ft = 0;
        const char *close_reason = NULL;
        int close_is_remote = 1;
        ok(quicly_get_close_reason(client, &close_ft, &close_reason, &close_is_remote) == QUICLY_TRANSPORT_ERROR_NO_VIABLE_PATH);
        ok(!close_is_remote && close_ft == QUICLY_FRAME_TYPE_PATH_ABANDON);
        free_multipath_regression_peers(client, server, orig);

        /* disable_active_migration restricts handshake address on client and declines route cleanly on server */
        quicly_context_t dm_saved = setup_multipath_regression_peers(&client, &server, 1);
        struct sockaddr_in alt = loopback_addr(23456);
        alt.sin_addr = fake_address.sin.sin_addr;
        local.sin_addr = fake_address.sin.sin_addr;
        ok(quicly_open_path(client, &fake_address.sa, (struct sockaddr *)&local) == QUICLY_ERROR_PACKET_IGNORED);
        ok(quicly_open_path(client, (struct sockaddr *)&alt, (struct sockaddr *)&local) == 0);
        get_path(client, 0)->address.remote.sin = alt;
        ok(quicly_open_path(client, &fake_address.sa, (struct sockaddr *)&local) == QUICLY_ERROR_PACKET_IGNORED);
        out_cnt = 1;
        ok(quicly_send(client, &dst_a, &src_a, &out_dg, &out_cnt, out_buf, sizeof(out_buf)) == 0 && out_cnt == 1);
        uint8_t copy_buf[1500];
        memcpy(copy_buf, out_dg.iov_base, out_dg.iov_len);
        struct iovec copy_dg = {.iov_base = copy_buf, .iov_len = out_dg.iov_len};
        ok(decode_packets(&dec, &out_dg, 1) == 1);
        ok(quicly_receive(server, &fake_address.sa, (struct sockaddr *)&local, &dec) == QUICLY_ERROR_PACKET_IGNORED);
        ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED && get_path(server, 1) == NULL);
        ok(decode_packets(&dec, &copy_dg, 1) == 1);
        ok(quicly_receive(server, NULL, (struct sockaddr *)&local, &dec) == 0 && get_path(server, 1) != NULL);
        free_multipath_regression_peers(client, server, dm_saved);
    }

    quic_ctx = orig;
    quic_now = orig_now;
}

static void test_multipath_scheduling(void)
{
    int64_t saved_now = quic_now;
    quicly_context_t orig = quic_ctx;

    /* multi-path round-robin active use and non-eviction when all path spaces are occupied */
    {
        test_rr_next_path_index = 0;
        quic_ctx.path_scheduler = &test_round_robin_path_scheduler;
        quicly_conn_t *client, *server;
        quicly_context_t saved =
            setup_multipath_regression_peers_limit(&client, &server, 0, QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT);
        struct sockaddr_in remotes[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT - 1],
            locals[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT - 1];
        for (size_t i = 0; i < PTLS_ELEMENTSOF(remotes); ++i) {
            remotes[i] = loopback_addr((uint16_t)(10000 + i));
            locals[i] = loopback_addr((uint16_t)(20000 + i));
            ok(quicly_open_path(client, (struct sockaddr *)&remotes[i], (struct sockaddr *)&locals[i]) == 0);
        }
        multipath_run(client, server, 5 * QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT, -1, -1);
        uint64_t sent_before[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
        for (size_t i = 0; i < QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT; ++i) {
            ok(quicly_is_path_available(client, i) && quicly_is_path_available(server, i));
            sent_before[i] = client->path_spaces[i]->num_packets.sent;
        }
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);
        for (size_t i = 0; i < 5 * QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT; ++i) {
            quicly_streambuf_egress_write(stream, "hello multipath test", 20);
            multipath_round(client, server, -1, -1);
        }
        for (size_t i = 0; i < QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT; ++i)
            ok(client->path_spaces[i]->num_packets.sent > sent_before[i]);
        size_t ignored;
        ok(open_path(client, &ignored, QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT, (struct sockaddr *)&remotes[0],
                     (struct sockaddr *)&locals[0]) == QUICLY_ERROR_PACKET_IGNORED);
        free_multipath_regression_peers(client, server, saved);
        quic_ctx = orig;
    }

    /* per-path pacing burst limit and progress wakeup */
    {
        quic_ctx.egress[0].pacing = 1;
        test_rr_next_path_index = 0;
        quic_ctx.path_scheduler = &test_round_robin_path_scheduler;
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_regression_peers(&client, &server, 0);
        open_multipath_test_path(client);
        multipath_run(client, server, 40, -1, -1);
        uint64_t sent_before[2];
        for (size_t i = 0; i < 2; ++i) {
            quicly_path_space_t *ps = client->path_spaces[i];
            ps->cc.cwnd = 1024 * 1024;
            ps->loss.rtt.latest = ps->loss.rtt.smoothed = 20000;
            quicly_pacer_reset(ps->pacer);
            sent_before[i] = ps->num_packets.bytes_sent;
        }
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);
        uint8_t data[30000] = {0};
        ok(quicly_streambuf_egress_write(stream, data, sizeof(data)) == 0);
        for (size_t i = 0; i < 32; ++i)
            transmit_multipath(client, server);
        for (size_t i = 0; i < 2; ++i) {
            uint64_t sent = client->path_spaces[i]->num_packets.bytes_sent - sent_before[i];
            ok(sent > 0 && sent <= QUICLY_PACER_BURST_HIGH * client->path_spaces[i]->max_udp_payload_size);
        }
        int64_t wake_at = quicly_get_first_timeout(client);
        ok(wake_at > quic_now && wake_at <= quic_now + 200);
        quic_now = wake_at;
        ok(transmit_multipath(client, server) != 0);
        free_multipath_regression_peers(client, server, saved);
        quic_ctx = orig;
    }

    /* single-PTO backup holdoff, blackhole failover + primary restoration, full-flight PTO=2 failover, and explicit DATAGRAM rank
     */
    static quicly_receive_datagram_frame_t receiver = {test_queue_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.receive_datagram_frame = &receiver;
    quic_ctx.egress[0].cc.initcwnd_packets = 32;
    quicly_path_scheduler_t *schedulers[] = {&quicly_default_path_scheduler, &test_round_robin_path_scheduler};
    for (size_t n = 0; n < PTLS_ELEMENTSOF(schedulers); ++n) {
        test_rr_next_path_index = 0;
        quicly_conn_t *client, *server;
        quicly_context_t saved = setup_multipath_scheduling_peers(&client, &server, schedulers[n]);
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);

        /* draining an explicit backup DATAGRAM while primary is cwnd-blocked must not leak stream data onto backup */
        ok(quicly_streambuf_egress_write(stream, "primary only", 12) == 0);
        uint32_t saved_cwnd = client->path_spaces[0]->cc.cwnd;
        client->path_spaces[0]->cc.cwnd = 0;
        ptls_iovec_t dg = ptls_iovec_init("explicit", 8);
        quicly_send_datagram_frames_path(client, 1, &dg, 1);
        ok(transmit_multipath(client, server) == 1 && quicly_get_num_datagram_frames_path(client, 1) == 0);
        ok(multipath_received_length(server, stream->stream_id) == 0);
        client->path_spaces[0]->cc.cwnd = saved_cwnd;

        /* single PTO on primary must not fail over to backup */
        uint64_t backup_before = client->path_spaces[1]->num_packets.bytes_sent;
        for (size_t i = 0; i < 1000 && client->path_spaces[0]->loss.pto_count <= 0; ++i)
            multipath_round(client, server, 0, 0);
        ok(client->path_spaces[0]->loss.pto_count == 1 && client->path_spaces[1]->num_packets.bytes_sent == backup_before);
        for (size_t i = 0; i < 200 && multipath_received_length(server, stream->stream_id) < 12; ++i)
            multipath_round(client, server, -1, -1);
        ok(multipath_received_length(server, stream->stream_id) == 12);

        /* full 30KB flight blackholed on primary requeues at PTO=2 onto backup; restoring primary returns traffic to path 0 */
        uint8_t bulk[30000];
        for (size_t i = 0; i < sizeof(bulk); ++i)
            bulk[i] = (uint8_t)(i * 7 + 3);
        ok(quicly_streambuf_egress_write(stream, bulk, sizeof(bulk)) == 0);
        while (transmit_multipath_with_loss(client, server, 0) != 0)
            ;
        for (size_t i = 0; i < 2000 && client->path_spaces[0]->loss.pto_count < 2; ++i)
            multipath_round(client, server, 0, 0);
        for (size_t i = 0; i < 50 && multipath_received_length(server, stream->stream_id) < 12 + sizeof(bulk); ++i)
            multipath_round(client, server, 0, 0);
        ok(multipath_received_length(server, stream->stream_id) == 12 + sizeof(bulk));

        for (size_t i = 0; i < 3000 && client->path_spaces[0]->loss.pto_count != 0; ++i)
            multipath_round(client, server, -1, -1);
        ok(client->path_spaces[0]->loss.pto_count == 0);
        multipath_run(client, server, 50, -1, -1);
        backup_before = client->path_spaces[1]->num_packets.bytes_sent;
        ok(quicly_streambuf_egress_write(stream, "restored", 8) == 0);
        multipath_run(client, server, 50, -1, -1);
        ok(multipath_received_length(server, stream->stream_id) == 20 + sizeof(bulk));
        ok(client->path_spaces[1]->num_packets.bytes_sent == backup_before);
        free_multipath_regression_peers(client, server, saved);
    }

    quic_ctx = orig;
    quic_now = saved_now;
}

typedef struct st_custom_recovery_policy_t {
    unsigned eligible;
    size_t preferred;
    size_t maintenance_packets, data_packets;
    int duplicate_packets;
    size_t received_datagrams;
} custom_recovery_policy_t;

static int custom_recovery_eligible(quicly_path_scheduler_t *self, quicly_conn_t *conn, size_t path_index)
{
    (void)self;
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    return path_index < 32 && (policy->eligible & (1u << path_index)) != 0;
}

static quicly_error_t custom_recovery_send_data(quicly_path_scheduler_t *self, quicly_conn_t *conn, quicly_send_context_t *s)
{
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    size_t count = 0, first = policy->preferred;
    quicly_path_stats_t health;
    if (quicly_get_path_stats(conn, first, &health) == 0 && health.pto_count >= 2)
        first ^= 1;
    for (size_t n = 0; n < 2; ++n) {
        size_t index = first ^ n;
        if (!custom_recovery_eligible(self, conn, index) || !quicly_is_path_available(conn, index))
            continue;
        quicly_error_t ret = quicly_send_on_path(conn, s, index, &count);
        if (ret != 0)
            return ret;
        if (count != 0) {
            policy->data_packets += count;
            break;
        }
    }
    return 0;
}

static int custom_recovery_can_send_data(quicly_path_scheduler_t *self, quicly_conn_t *conn, size_t path_index)
{
    quicly_path_stats_t st, alt;
    if (!custom_recovery_eligible(self, conn, path_index) || quicly_get_path_stats(conn, path_index, &st) != 0)
        return 0;
    if (st.pto_count < 2)
        return 1;
    size_t other = path_index ^ 1;
    return !custom_recovery_eligible(self, conn, other) || !quicly_is_path_available(conn, other) ||
           quicly_get_path_stats(conn, other, &alt) != 0 || alt.pto_count >= 2;
}

static quicly_path_scheduler_t custom_recovery_scheduler = {custom_recovery_send_data, custom_recovery_eligible,
                                                            custom_recovery_can_send_data};

static void custom_recovery_receive_datagram(quicly_receive_datagram_frame_t *self, quicly_conn_t *conn, ptls_iovec_t payload)
{
    (void)self;
    (void)payload;
    custom_recovery_policy_t *policy = *quicly_get_data(conn);
    ++policy->received_datagrams;
}

typedef struct st_custom_recovery_fixture_t {
    quicly_conn_t *client, *server;
    custom_recovery_policy_t client_policy, server_policy;
    quicly_context_t saved;
    int64_t saved_now, bound;
} custom_recovery_fixture_t;

static void custom_recovery_setup(custom_recovery_fixture_t *f)
{
    *f = (custom_recovery_fixture_t){
        .saved = quic_ctx, .saved_now = quic_now, .client_policy = {.eligible = 3}, .server_policy = {.eligible = 3}};
    static quicly_receive_datagram_frame_t receiver = {custom_recovery_receive_datagram};
    quic_ctx.transport_params.max_datagram_frame_size = 1200;
    quic_ctx.transport_params.max_data = 1024 * 1024;
    quic_ctx.transport_params.max_stream_data.bidi_local = quic_ctx.transport_params.max_stream_data.bidi_remote = 1024 * 1024;
    quic_ctx.receive_datagram_frame = &receiver;
    setup_multipath_scheduling_peers(&f->client, &f->server, &quicly_default_path_scheduler);
    *quicly_get_data(f->client) = &f->client_policy;
    *quicly_get_data(f->server) = &f->server_policy;
    quic_ctx.path_scheduler = &custom_recovery_scheduler;
    f->bound = (int64_t)ceil(64 * get_max_pto(f->client)) + 100;
}

static void custom_recovery_free(custom_recovery_fixture_t *f)
{
    free_multipath_regression_peers(f->client, f->server, f->saved);
    quic_now = f->saved_now;
}

static size_t custom_recovery_transmit(quicly_conn_t *src, quicly_conn_t *dst, unsigned drop, size_t budget)
{
    quicly_address_t remote, local;
    struct iovec datagrams[16];
    uint8_t buffer[16 * 1500];
    size_t count = budget;
    quicly_stats_t before, after;
    quicly_get_stats(src, &before);
    ok(quicly_send(src, &remote, &local, datagrams, &count, buffer, budget * 1500) == 0);
    quicly_get_stats(src, &after);
    if (count != 0) {
        custom_recovery_policy_t *policy = *quicly_get_data(src);
        if (before.num_frames_sent.stream == after.num_frames_sent.stream &&
            before.num_frames_sent.datagram == after.num_frames_sent.datagram)
            policy->maintenance_packets += count;
        size_t path = local.sin.sin_port == 0 ? 0 : 1;
        ok(custom_recovery_eligible(&custom_recovery_scheduler, src, path) && count <= budget);
        if ((drop & (1u << path)) == 0) {
            quicly_decoded_packet_t decoded[32];
            size_t packets = decode_packets(decoded, datagrams, count);
            for (size_t i = 0; i < packets; ++i) {
                quicly_error_t ret = quicly_receive(dst, &remote.sa, &local.sa, decoded + i);
                ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
                if (policy->duplicate_packets) {
                    ret = quicly_receive(dst, &remote.sa, &local.sa, decoded + i);
                    ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
                }
            }
        }
    }
    return count;
}

static void custom_recovery_round(custom_recovery_fixture_t *f, unsigned drop, size_t budget)
{
    ++quic_now;
    custom_recovery_transmit(f->client, f->server, drop, budget);
    custom_recovery_transmit(f->server, f->client, drop, budget);
}

static size_t multipath_progress_nat_transmit(custom_recovery_fixture_t *f, int from_client)
{
    quicly_conn_t *src = from_client ? f->client : f->server, *dst = from_client ? f->server : f->client;
    quicly_address_t remote, local;
    struct iovec datagram;
    uint8_t buffer[1500];
    size_t count = 1;
    ok(quicly_send(src, &remote, &local, &datagram, &count, buffer, sizeof(buffer)) == 0);
    if (count != 0) {
        if (from_client && local.sin.sin_port == htons(20000))
            local.sin.sin_port = htons(20001);
        if (!from_client && remote.sin.sin_port == htons(20001))
            remote.sin.sin_port = htons(20000);
        quicly_decoded_packet_t decoded[4];
        size_t packets = decode_packets(decoded, &datagram, count);
        for (size_t i = 0; i < packets; ++i)
            ok(quicly_receive(dst, &remote.sa, &local.sa, decoded + i) == 0);
    }
    return count != 0 ? datagram.iov_len : 0;
}

static void test_multipath_custom_recovery(void)
{
    /* sustained bidirectional blackhole failover + duplicate-packet resilience + maintenance recovery */
    {
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        quicly_stream_t *stream, *reverse;
        ok(quicly_open_stream(f.client, &stream, 0) == 0 && quicly_open_stream(f.server, &reverse, 0) == 0);
        uint8_t initial[8000];
        for (size_t i = 0; i < sizeof(initial); ++i)
            initial[i] = (uint8_t)(i * 13);
        ok(quicly_streambuf_egress_write(stream, initial, sizeof(initial)) == 0);
        ok(custom_recovery_transmit(f.client, f.server, 1, 16) != 0);
        f.server_policy.duplicate_packets = 1;
        f.server_policy.preferred = 1;
        int64_t until = quic_now + f.bound;
        while (quic_now < until && multipath_received_length(f.server, stream->stream_id) < sizeof(initial)) {
            ok(quicly_streambuf_egress_write(stream, initial, 64) == 0);
            ok(quicly_streambuf_egress_write(reverse, initial, 64) == 0);
            custom_recovery_round(&f, 1, 16);
        }
        ok(multipath_received_length(f.server, stream->stream_id) >= sizeof(initial));
        quicly_path_stats_t health = {0};
        ok(quicly_get_path_stats(f.client, 0, &health) == 0 && health.pto_count >= 2 && !health.abandoned);
        f.client_policy.preferred = 1;
        until = quic_now + f.bound;
        while (quic_now < until && health.pto_count != 0) {
            custom_recovery_round(&f, 0, 1);
            ok(quicly_get_path_stats(f.client, 0, &health) == 0);
        }
        ok(health.pto_count == 0 && f.client_policy.maintenance_packets != 0);

        /* dynamic socket removal routes over path 1; zero eligible sockets still advance to idle expiration */
        f.server_policy.duplicate_packets = 0;
        f.client_policy.eligible = f.server_policy.eligible = 2;
        size_t before_len = multipath_received_length(f.server, stream->stream_id);
        ok(quicly_streambuf_egress_write(stream, "path1", 5) == 0);
        until = quic_now + f.bound;
        while (quic_now < until && multipath_received_length(f.server, stream->stream_id) < before_len + 5)
            custom_recovery_round(&f, 0, 16);
        ok(multipath_received_length(f.server, stream->stream_id) >= before_len + 5);

        f.client_policy.eligible = f.server_policy.eligible = 0;
        int64_t expires = f.client->idle_timeout.at;
        for (size_t calls = 0; calls < 64 && quic_now < expires; ++calls) {
            custom_recovery_transmit(f.client, f.server, 0, 1);
            int64_t next = quicly_get_first_timeout(f.client);
            ok(next > quic_now);
            quic_now = next;
        }
        quicly_address_t remote, local;
        struct iovec pkt;
        uint8_t buf[1500];
        size_t cnt = 1;
        ok(quicly_send(f.client, &remote, &local, &pkt, &cnt, buf, sizeof(buf)) == QUICLY_ERROR_FREE_CONNECTION && cnt == 0);
        custom_recovery_free(&f);
    }

    /* path stats across candidate/reused slots, maintenance idempotence, cwnd/pacer/amp limits, and 0-socket close/handshake */
    {
        quicly_context_t saved_ctx = quic_ctx;
        quic_ctx.egress[0].pacing = 1;
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        quicly_path_stats_t h = {0};
        ok(quicly_get_path_stats(f.client, 1, &h) == 0 && h.validated && h.peer_is_backup && !h.probe_only);
        ok(quicly_get_path_stats(f.client, SIZE_MAX, &h) == -1 && quicly_get_path_stats(f.client, 3, &h) == -1);

        struct sockaddr_in remote = loopback_addr(30000), local = loopback_addr(40000);
        size_t cand;
        lock_now(f.client, 1);
        ok(open_path(f.client, &cand, 1, (struct sockaddr *)&remote, (struct sockaddr *)&local) == 0);
        unlock_now(f.client);
        ok(quicly_get_path_stats(f.client, cand, &h) == 0 && h.probe_only && !h.validated);
        ok(delete_path(f.client, cand) == 0 && quicly_get_path_stats(f.client, cand, &h) == 0 && h.abandoned && !h.validated);
        ok(destroy_path_state(f.client, cand) == 0 && quicly_get_path_stats(f.client, cand, &h) == -1);

        /* maintenance idempotence and cwnd/pacer/amplification bounds */
        quicly_stream_t *stream;
        ok(quicly_open_stream(f.client, &stream, 0) == 0 && quicly_streambuf_egress_write(stream, "bounded", 7) == 0);
        ptls_iovec_t sym = ptls_iovec_init("symbol", 6);
        quicly_send_datagram_frames_path(f.client, 1, &sym, 1);
        f.client->path_spaces[1]->loss.alarm_at = quic_now;
        quicly_send_context_t s;
        struct iovec dgram;
        uint8_t buf[1500];
        test_setup_send_context(f.client, &s, &dgram, buf, sizeof(buf));
        ok(send_path_maintenance(f.client, &s) == 0 && s.num_datagrams == 1);
        uint64_t pn_after = f.client->path_spaces[1]->packet_number;
        ok(send_path_maintenance(f.client, &s) == 0 && f.client->path_spaces[1]->packet_number == pn_after);
        ok(quicly_get_num_datagram_frames_path(f.client, 1) == 1);
        unlock_now(f.client);

        f.client_policy.eligible = 2;
        quicly_path_space_t *ps = f.client->path_spaces[1];
        uint32_t cwnd = ps->cc.cwnd;
        ps->cc.cwnd = 0;
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 0 && quicly_get_first_timeout(f.client) > quic_now);
        ps->cc.cwnd = cwnd;
        ps->pacer->at = quic_now;
        ps->pacer->bytes_sent = (size_t)calc_pacer_send_rate(ps) * 100 + 20 * ps->max_udp_payload_size;
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 0 && quicly_get_first_timeout(f.client) > quic_now);
        ps->loss.alarm_at = quic_now;
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1 && multipath_received_length(f.server, stream->stream_id) == 0);

        f.server_policy.eligible = 2;
        struct st_quicly_conn_path_t *srv_path = get_path(f.server, 1);
        srv_path->path_challenge.send_at = quic_now + 1000;
        srv_path->path_challenge.address_validated = 0;
        srv_path->bytes_received = 1;
        srv_path->bytes_sent = quic_ctx.pre_validation_amplification_limit;
        f.server->path_spaces[1]->loss.alarm_at = quic_now;
        ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 0 && quicly_get_first_timeout(f.server) > quic_now);
        srv_path->bytes_received += 1500;
        f.server->path_spaces[1]->loss.alarm_at = quic_now;
        ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 1);

        /* path 0 PATH_RESPONSE under cwnd == 0; then 0-socket closing finishes in bounded steps */
        f.client_policy.eligible = 3;
        f.client->path_spaces[0]->cc.cwnd = 0;
        get_path(f.client, 0)->path_response.send_ = 1;
        recalc_send_probe_at(f.client);
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1 && !get_path(f.client, 0)->path_response.send_);

        f.client_policy.eligible = 0;
        ok(quicly_close(f.client, 0, "test") == 0);
        int64_t next = quicly_get_first_timeout(f.client);
        ok(next > quic_now);
        quic_now = next;
        quicly_address_t r_a, l_a;
        size_t cnt = 1;
        ok(quicly_send(f.client, &r_a, &l_a, &dgram, &cnt, buf, sizeof(buf)) == QUICLY_ERROR_FREE_CONNECTION);
        custom_recovery_free(&f);
        quic_ctx = saved_ctx;

        /* single-path handshake timeout with 0 eligible sockets */
        int64_t saved_now = quic_now;
        custom_recovery_policy_t sp_pol = {.eligible = 0};
        quic_ctx.path_scheduler = &custom_recovery_scheduler;
        quicly_conn_t *sp_client;
        ok(quicly_connect(&sp_client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                          NULL, NULL, NULL) == 0);
        *quicly_get_data(sp_client) = &sp_pol;
        next = quicly_get_first_timeout(sp_client);
        ok(next > quic_now && next != INT64_MAX);
        quic_now = next;
        cnt = 1;
        ok(quicly_send(sp_client, &r_a, &l_a, &dgram, &cnt, buf, sizeof(buf)) == QUICLY_ERROR_FREE_CONNECTION);
        quicly_free(sp_client);
        quic_ctx = saved_ctx;
        quic_now = saved_now;
    }

    /* short validation -> fresh-nonce full-MTU validation, small NAT rebinding, retry limit, and failed candidate non-promotion */
    {
        custom_recovery_fixture_t f;
        custom_recovery_setup(&f);
        f.server_policy.eligible = 2;
        struct st_quicly_conn_path_t *path = get_path(f.server, 1);
        path->path_challenge.send_at = quic_now;
        path->path_challenge.address_validated = path->path_challenge.sent_full_size = 0;
        path->path_challenge.num_sent = 0;
        path->validated = 0;
        path->probe_only = 1;
        path->bytes_received = 100;
        path->bytes_sent = 0;
        recalc_send_probe_at(f.server);
        uint8_t short_nonce[QUICLY_PATH_CHALLENGE_DATA_LEN];
        memcpy(short_nonce, path->path_challenge.data, sizeof(short_nonce));
        ok(custom_recovery_transmit(f.server, f.client, 0, 16) == 1 && !path->path_challenge.sent_full_size);
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1 && path->path_challenge.address_validated && path->probe_only);
        ok(memcmp(short_nonce, path->path_challenge.data, sizeof(short_nonce)) != 0);
        ok(custom_recovery_transmit(f.server, f.client, 0, 1) == 1 && path->path_challenge.sent_full_size);
        multipath_progress_deliver_response(f.server, 1, short_nonce);
        ok(path->probe_only);
        ok(custom_recovery_transmit(f.client, f.server, 0, 1) == 1 && !path->probe_only && path->validated);
        custom_recovery_free(&f);

        /* small NAT rebinding on server */
        custom_recovery_setup(&f);
        ok(f.client->path_spaces[1]->max_udp_payload_size == QUICLY_MIN_CLIENT_INITIAL_SIZE &&
           f.client->path_spaces[1]->loss.rtt.latest > 0);
        multipath_run(f.client, f.server, 30, -1, -1);
        f.client_policy.eligible = 2;
        f.server_policy.eligible = UINT_MAX;
        quicly_stream_t *stream;
        ok(quicly_open_stream(f.client, &stream, 0) == 0 && quicly_streambuf_egress_write(stream, "rebind", 6) == 0);
        size_t received = multipath_progress_nat_transmit(&f, 1);
        ok(received != 0 && received < 400);
        size_t idx = SIZE_MAX;
        for (size_t i = 0; i < QUICLY_MAX_PATH_INDICES; ++i)
            if (get_path(f.server, i) != NULL && get_path(f.server, i)->address.remote.sin.sin_port == htons(20001))
                idx = i;
        ok(idx != SIZE_MAX);
        struct st_quicly_conn_path_t *rebound = get_path(f.server, idx);
        /* non-probing frame clears probe_only without promoting until validated */
        ok(!rebound->probe_only && !rebound->validated && get_path(f.server, 1) != rebound);
        for (size_t i = 0; i < 100 && get_path(f.server, 1) != rebound; ++i) {
            ++quic_now;
            multipath_progress_nat_transmit(&f, 0);
            multipath_progress_nat_transmit(&f, 1);
        }
        ok(get_path(f.server, 1) == rebound && multipath_received_length(f.server, stream->stream_id) == 6);

        /* candidate validation failure under 1-packet amplification limit expires cleanly without replacing working address */
        struct st_quicly_conn_path_t *working = get_path(f.server, 0);
        struct sockaddr_in dead_peer = loopback_addr(31337);
        size_t dead_cand;
        lock_now(f.server, 1);
        ok(open_path(f.server, &dead_cand, 0, (struct sockaddr *)&dead_peer, &fake_address.sa) == 0);
        unlock_now(f.server);
        struct st_quicly_conn_path_t *dead_path = get_path(f.server, dead_cand);
        dead_path->bytes_received = 1200;
        quicly_address_t dst, src;
        struct iovec pkt;
        uint8_t buf[1500];
        for (size_t i = 0; i <= quic_ctx.max_probe_packets; ++i) {
            if (dead_path->path_challenge.send_at > quic_now)
                quic_now = dead_path->path_challenge.send_at;
            size_t cnt = 1;
            ok(quicly_send(f.server, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0);
            ok(dead_path->bytes_sent <= 3 * dead_path->bytes_received);
        }
        if (dead_path->path_challenge.send_at > quic_now)
            quic_now = dead_path->path_challenge.send_at;
        size_t cnt = 1;
        ok(quicly_send(f.server, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && dead_path->abandoned);
        uint8_t ping = QUICLY_FRAME_TYPE_PING;
        ok(send_raw_1rtt_frame(f.client, f.server, 0, &fake_address.sa, (struct sockaddr *)&dead_peer, &ping, 1) == 0);
        ok(get_path(f.server, 0) == working && !working->abandoned);

        /* 0-length + non-empty DATAGRAM payloads survive candidate promotion and old DCID is retired */
        size_t c_cand = encode_flat_path_index(1, 1);
        lock_now(f.client, 0);
        ok(new_path(f.client, c_cand, 1, (struct sockaddr *)&dead_peer, &fake_address.sa) == 0);
        struct st_quicly_conn_path_t *cp = get_path(f.client, c_cand);
        cp->path_challenge.sent_full_size = 1;
        cp->path_challenge.num_sent = 1;
        multipath_progress_deliver_response(f.client, c_cand, cp->path_challenge.data);
        ok(cp->validated && cp->probe_only && !quicly_is_path_available(f.client, c_cand));
        ptls_iovec_t dgs[2] = {ptls_iovec_init(NULL, 0), ptls_iovec_init("hi", 2)};
        quicly_send_datagram_frames_path(f.client, 1, dgs, 2);
        size_t retired_before = f.client->path_spaces[1]->remote_cid_set.retired.count;
        cp->probe_only = 0;
        ok(promote_path(f.client, c_cand) == 0);
        unlock_now(f.client);
        ok(f.client->path_spaces[1]->remote_cid_set.retired.count == retired_before + 1);
        ok(quicly_get_num_datagram_frames_path(f.client, 1) == 2);

        /* path_id == 255 resolves in local_cid_path_map; out-of-order CID retirement keeps next_expected_cid_seq monotonic;
         * client ignores unsolicited server src_addr; server omits PING on path-0 candidate PATH_RESPONSE */
        if (f.server->path_spaces[2] != NULL) {
            free_path_space(f.server->path_spaces[2]);
            f.server->path_spaces[2] = NULL;
        }
        f.server->super.local.max_path_id = QUICLY_MAX_PATH_ID;
        f.server->super.remote.max_path_id = QUICLY_MAX_PATH_ID;
        lock_now(f.server, 0);
        size_t map_capacity = f.server->local_cid_path_map_capacity;
        ok(map_capacity == 16);
        uint8_t old_tag = f.server->path_spaces[0]->local_cid_set.cids[0].cid_tag;
        f.server->next_local_cid_tag = (uint8_t)(map_capacity + 1);
        ok(alloc_path_space(f.server, 2, QUICLY_MAX_PATH_ID) == 0);
        ok(f.server->local_cid_path_map_capacity == 2 * map_capacity);
        uint32_t resolved_pid = UINT32_MAX;
        quicly_decoded_packet_t fake_pkt = {0};
        fake_pkt.cid.dest.plaintext.path_id = old_tag;
        ok(resolve_local_cid_path_id(f.server, &fake_pkt, &resolved_pid) && resolved_pid == 0);
        fake_pkt.cid.dest.plaintext.path_id = (uint8_t)map_capacity;
        ok(!resolve_local_cid_path_id(f.server, &fake_pkt, &resolved_pid));
        fake_pkt.cid.dest.plaintext.path_id = f.server->path_spaces[2]->local_cid_set.cids[0].cid_tag;
        ok(resolve_local_cid_path_id(f.server, &fake_pkt, &resolved_pid) && resolved_pid == QUICLY_MAX_PATH_ID);

        uint8_t c2_bytes[8] = {7, 7, 7, 7, 7, 7, 7, 2}, srt2[16] = {2};
        quicly_new_connection_id_frame_t ncid2 = {
            .sequence = 2, .retire_prior_to = 0, .cid = ptls_iovec_init(c2_bytes, 8), .stateless_reset_token = srt2};
        ok(register_remote_cid(f.server, f.server->path_spaces[2], &ncid2) == 0);
        ok(quicly_remote_cid_unregister(&f.server->path_spaces[2]->remote_cid_set, 2) == 0);
        schedule_path_cids_blocked(f.server, f.server->path_spaces[2]);
        ok(f.server->path_spaces[2]->path_cids_blocked.sequence == 3);
        unlock_now(f.server);

        /* client rejects short-header packet from unsolicited server address */
        struct sockaddr_in rogue_srv = loopback_addr(44444);
        ok(send_raw_1rtt_frame(f.server, f.client, 0, &fake_address.sa, (struct sockaddr *)&rogue_srv, &ping, 1) ==
           QUICLY_ERROR_PACKET_IGNORED);

        /* server PATH_RESPONSE on a path-0 candidate tuple must not append PING */
        size_t p0_cand = encode_flat_path_index(0, 1);
        lock_now(f.server, 0);
        if (get_path(f.server, p0_cand) != NULL)
            destroy_path_state(f.server, p0_cand);
        ok(new_path(f.server, p0_cand, 0, (struct sockaddr *)&rogue_srv, &fake_address.sa) == 0);
        get_path(f.server, p0_cand)->bytes_received = 5000;
        get_path(f.server, p0_cand)->path_challenge.send_at = INT64_MAX;
        get_path(f.server, p0_cand)->path_response.send_ = 1;
        recalc_send_probe_at(f.server);
        unlock_now(f.server);
        uint64_t srv_pings_before = f.server->super.stats.num_frames_sent.ping;
        f.server_policy.eligible = 1u << p0_cand;
        cnt = 1;
        ok(quicly_send(f.server, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1);
        ok(f.server->super.stats.num_frames_sent.ping == srv_pings_before);

        /* unvalidated replacement cannot allow abandoning working path; MTU-oversized DATAGRAM drops without PADDING-only
         * in-flight; custom can_send_data backup override wakes timeout & sends; empty DATAGRAM encodes cleanly; slot-0 CID
         * retirement allows rebinding; closing on secondary path emits only short-header 1-RTT packet and ignores expired
         * open-state idle_timeout */
        get_path(f.client, 1)->probe_only = 1;
        ok(quicly_abandon_path(f.client, 0, 0) == QUICLY_ERROR_PACKET_IGNORED && !get_path(f.client, 0)->abandoned);
        get_path(f.client, 1)->probe_only = 0;

        /* candidate index is rejected by per-path DATAGRAM queue helpers */
        quicly_send_datagram_frames_path(f.client, encode_flat_path_index(1, 1), dgs + 1, 1);
        ok(quicly_get_num_datagram_frames_path(f.client, encode_flat_path_index(1, 1)) == 0 &&
           quicly_get_max_datagram_frames_path(f.client, encode_flat_path_index(1, 1)) == 0);

        /* emit the queued 0-length + non-empty DATAGRAM payloads + drop MTU-oversized payload without in-flight PADDING */
        f.client->egress.pending_flows = 0;
        f.client->path_spaces[0]->pn_space->send_ack_at = INT64_MAX;
        f.client->path_spaces[0]->loss.alarm_at = INT64_MAX;
        f.client->path_spaces[1]->pn_space->send_ack_at = INT64_MAX;
        f.client->path_spaces[1]->loss.alarm_at = INT64_MAX;
        f.client->super.remote.transport_params.max_datagram_frame_size = 2000;
        uint8_t mtu_over_bytes[1250] = {0};
        ptls_iovec_t mtu_over = ptls_iovec_init(mtu_over_bytes, sizeof(mtu_over_bytes));
        quicly_send_datagram_frames_path(f.client, 1, &mtu_over, 1);
        cnt = 1;
        uint64_t dgs_before_empty = f.client->super.stats.num_frames_sent.datagram;
        ok(quicly_send(f.client, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1 &&
           f.client->super.stats.num_frames_sent.datagram == dgs_before_empty + 2 &&
           quicly_get_num_datagram_frames_path(f.client, 1) == 0);
        ok(!quicly_has_pending_stream_data(f.server));
        quicly_stream_t *bstream;
        ok(quicly_open_stream(f.client, &bstream, 0) == 0 && quicly_streambuf_egress_write(bstream, "bk", 2) == 0);
        ok(quicly_has_pending_stream_data(f.client));
        quicly_context_t *orig_cctx = f.client->super.ctx, bctx = *orig_cctx;
        quicly_path_scheduler_t bsched = quicly_default_path_scheduler;
        bsched.can_send_data = backup_only_can_send_data;
        bctx.path_scheduler = &bsched;
        f.client->super.ctx = &bctx;
        ok(quicly_get_first_timeout(f.client) <= quic_now);
        cnt = 1;
        ok(quicly_send(f.client, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1 &&
           dst.sin.sin_port == get_path(f.client, 1)->address.remote.sin.sin_port);
        f.client->super.ctx = orig_cctx;

        f.server->path_spaces[1]->local_cid_set.cids[0].state = QUICLY_LOCAL_CID_STATE_IDLE;
        size_t reb_cand;
        struct sockaddr_in reb_peer = loopback_addr(45555);
        lock_now(f.server, 1);
        ok(open_path(f.server, &reb_cand, 1, (struct sockaddr *)&reb_peer, &fake_address.sa) == 0);
        destroy_path_state(f.server, reb_cand);
        unlock_now(f.server);

        /* unbound DATAGRAM too large for 1200-MTU path 1 stays queued without stalling smaller DATAGRAMs behind it */
        uint8_t ub_bytes[1200] = {0x42}, ub_small_bytes[64] = {0x24};
        ptls_iovec_t ub_dgs[2] = {ptls_iovec_init(ub_bytes, sizeof(ub_bytes)),
                                  ptls_iovec_init(ub_small_bytes, sizeof(ub_small_bytes))};
        f.client->egress.pending_flows = 0;
        f.client->path_spaces[0]->pn_space->send_ack_at = INT64_MAX;
        f.client->path_spaces[0]->loss.alarm_at = INT64_MAX;
        f.client->path_spaces[1]->pn_space->send_ack_at = INT64_MAX;
        f.client->path_spaces[1]->loss.alarm_at = INT64_MAX;
        quicly_send_datagram_frames(f.client, ub_dgs, 2);
        /* 1200-MTU path 1 immediately wakes and emits the trailing 64-byte datagram while retaining the 1200-byte datagram */
        f.client_policy.eligible = 2;
        ok(quicly_get_first_timeout(f.client) <= quic_now);
        cnt = 1;
        uint64_t ub_before = f.client->super.stats.num_frames_sent.datagram;
        ok(quicly_send(f.client, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1 &&
           dst.sin.sin_port == get_path(f.client, 1)->address.remote.sin.sin_port &&
           f.client->super.stats.num_frames_sent.datagram == ub_before + 1 && f.client->egress.datagram_frame_payloads.count == 1);
        /* with only the 1200-byte datagram left, 1200-MTU path 1 does not spin */
        ok(quicly_get_first_timeout(f.client) > quic_now);
        cnt = 1;
        ok(quicly_send(f.client, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 0 &&
           f.client->egress.datagram_frame_payloads.count == 1);
        f.client_policy.eligible = 3;
        ok(quicly_get_first_timeout(f.client) <= quic_now);
        cnt = 1;
        ok(quicly_send(f.client, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1 &&
           dst.sin.sin_port == get_path(f.client, 0)->address.remote.sin.sin_port &&
           f.client->super.stats.num_frames_sent.datagram == ub_before + 2 && !quicly_has_datagram_frames(f.client));

        /* rotated high DCID sequence number lookup, latched CID limit on PATH_CIDS_BLOCKED, and per-DATAGRAM backup preference */
        uint64_t saved_dcid_seq = get_path(f.client, 0)->dcid;
        uint64_t saved_slot_seq = f.client->path_spaces[0]->remote_cid_set.cids[0].sequence;
        f.client->path_spaces[0]->remote_cid_set.cids[0].sequence =
            PTLS_ELEMENTSOF(f.client->path_spaces[0]->remote_cid_set.cids) + 5;
        get_path(f.client, 0)->dcid = f.client->path_spaces[0]->remote_cid_set.cids[0].sequence;
        ok(path_max_datagram_frame_space(f.client, 0) > 0);
        f.client->path_spaces[0]->remote_cid_set.cids[0].sequence = saved_slot_seq;
        get_path(f.client, 0)->dcid = saved_dcid_seq;

        uint64_t saved_ctx_cid_limit = f.client->super.ctx->transport_params.active_connection_id_limit;
        uint8_t saved_conn_cid_limit = f.client->local_cid_limit;
        uint64_t saved_largest_exp = f.client->path_spaces[1]->remote_cid_set._largest_sequence_expected;
        uint64_t saved_next_exp = f.client->path_spaces[1]->next_expected_cid_seq;
        f.client->local_cid_limit = 2;
        f.client->super.ctx->transport_params.active_connection_id_limit = QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT;
        f.client->path_spaces[1]->remote_cid_set._largest_sequence_expected = 1;
        f.client->path_spaces[1]->next_expected_cid_seq = 0;
        f.client->path_spaces[1]->path_cids_blocked.sender = QUICLY_SENDER_STATE_NONE;
        schedule_path_cids_blocked(f.client, f.client->path_spaces[1]);
        ok(f.client->path_spaces[1]->path_cids_blocked.sequence == 0);
        f.client->path_spaces[1]->path_cids_blocked.sender = QUICLY_SENDER_STATE_NONE;
        f.client->path_spaces[1]->remote_cid_set._largest_sequence_expected = saved_largest_exp;
        f.client->path_spaces[1]->next_expected_cid_seq = saved_next_exp;
        f.client->local_cid_limit = saved_conn_cid_limit;
        f.client->egress.pending_flows = 0;
        f.client->super.ctx->transport_params.active_connection_id_limit = saved_ctx_cid_limit;

        /* built-in scheduler: 1280-MTU backup path 0 sends only the 1200B datagram and leaves 64B for 1200-MTU primary path 1 */
        quicly_path_scheduler_t *saved_sched = f.client->super.ctx->path_scheduler;
        f.client->super.ctx->path_scheduler = &quicly_default_path_scheduler;
        f.client->path_spaces[0]->is_backup = 1;
        f.client->path_spaces[1]->is_backup = 0;
        f.client->path_spaces[0]->pn_space->send_ack_at = INT64_MAX;
        f.client->path_spaces[0]->loss.alarm_at = INT64_MAX;
        f.client->path_spaces[1]->pn_space->send_ack_at = INT64_MAX;
        f.client->path_spaces[1]->loss.alarm_at = INT64_MAX;
        quicly_send_datagram_frames(f.client, ub_dgs, 2);
        quicly_send_context_t bk_s = {.current = {.first_byte = -1},
                                      .datagrams = &pkt,
                                      .max_datagrams = 1,
                                      .payload_buf = {.datagram = buf, .end = buf + sizeof(buf)}};
        lock_now(f.client, 0);
        uint64_t bk_dg_before = f.client->super.stats.num_frames_sent.datagram;
        size_t bk_pkts = 0;
        ok(quicly_send_on_path(f.client, &bk_s, 0, &bk_pkts) == 0 && bk_pkts == 1 &&
           f.client->super.stats.num_frames_sent.datagram == bk_dg_before + 1 &&
           f.client->egress.datagram_frame_payloads.count == 1);
        unlock_now(f.client);
        cnt = 1;
        ok(quicly_send(f.client, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1 &&
           dst.sin.sin_port == get_path(f.client, 1)->address.remote.sin.sin_port &&
           f.client->super.stats.num_frames_sent.datagram == bk_dg_before + 2 && !quicly_has_datagram_frames(f.client));
        f.client->path_spaces[0]->is_backup = 0;
        f.client->super.ctx->path_scheduler = saved_sched;

        /* retiring path zero's final CID on another active path succeeds after tag exhaustion, while connection-last fails */
        f.server->next_local_cid_tag = QUICLY_MAX_PATH_ID;
        size_t p0_sz = quicly_local_cid_get_size(&f.server->path_spaces[0]->local_cid_set);
        while (path_space_has_local_cid(f.server->path_spaces[0])) {
            uint64_t seq = UINT64_MAX;
            for (size_t ci = 0; ci < p0_sz; ++ci) {
                if (f.server->path_spaces[0]->local_cid_set.cids[ci].state != QUICLY_LOCAL_CID_STATE_IDLE) {
                    seq = f.server->path_spaces[0]->local_cid_set.cids[ci].sequence;
                    break;
                }
            }
            assert(seq != UINT64_MAX);
            uint8_t rcid_buf[16];
            size_t rcid_len = (size_t)(quicly_encode_retire_connection_id_frame(rcid_buf, seq) - rcid_buf);
            ok(send_raw_1rtt_frame(f.client, f.server, 1, &get_path(f.server, 1)->address.local.sa,
                                   &get_path(f.client, 1)->address.local.sa, rcid_buf, rcid_len) == 0);
        }
        ok(quicly_get_state(f.server) == QUICLY_STATE_CONNECTED && !path_space_has_local_cid(f.server->path_spaces[0]));
        size_t p1_sz = quicly_local_cid_get_size(&f.server->path_spaces[1]->local_cid_set);
        struct st_quicly_handle_payload_state_t dummy_st = {0};
        while (1) {
            size_t p1_active = 0;
            uint64_t victim_seq = UINT64_MAX;
            for (size_t ci = 0; ci < p1_sz; ++ci) {
                if (f.server->path_spaces[1]->local_cid_set.cids[ci].state != QUICLY_LOCAL_CID_STATE_IDLE) {
                    victim_seq = f.server->path_spaces[1]->local_cid_set.cids[ci].sequence;
                    ++p1_active;
                }
            }
            if (p1_active <= 1) {
                ok(p1_active == 1 && victim_seq != UINT64_MAX);
                ok(retire_local_cid(f.server, &dummy_st, f.server->path_spaces[1], victim_seq) ==
                   QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
                break;
            }
            ok(retire_local_cid(f.server, &dummy_st, f.server->path_spaces[1], victim_seq) == 0);
        }

        f.server_policy.eligible = 3;
        f.server->super.remote.address_validation.validated = 0;
        get_path(f.server, 0)->path_challenge.address_validated = 0;
        get_path(f.server, 0)->bytes_received = 100;
        get_path(f.server, 0)->bytes_sent = 0;
        ok(quicly_close(f.server, 0, "bye") == 0);
        f.server->idle_timeout.at = quic_now - 1;
        cnt = 1;
        ok(quicly_send(f.server, &dst, &src, &pkt, &cnt, buf, sizeof(buf)) == 0 && cnt == 1 &&
           dst.sin.sin_port == get_path(f.server, 1)->address.remote.sin.sin_port && !QUICLY_PACKET_IS_LONG_HEADER(buf[0]));
        custom_recovery_free(&f);
    }
}

/* loss statistics must not depend on how many random bytes unrelated tests consumed */
static void test_lossy_isolated(void)
{
    static const uint8_t key[PTLS_AES128_KEY_SIZE] = {0}, iv[PTLS_AES_IV_SIZE] = {0};
    ptls_cipher_context_t *saved = test_random_cipher;
    test_random_cipher = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, key);
    assert(test_random_cipher != NULL);
    ptls_cipher_init(test_random_cipher, iv);
    test_lossy();
    ptls_cipher_free(test_random_cipher);
    test_random_cipher = saved;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--active-connection-id-limit") == 0) {
        printf("%" PRIu64 "\n", quicly_spec_context.transport_params.active_connection_id_limit);
        return 0;
    }

    static ptls_iovec_t cert;
    static ptls_openssl_sign_certificate_t cert_signer;
    static ptls_context_t tlsctx = {.random_bytes = test_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .certificates = {&cert, 1},
                                    .sign_certificate = &cert_signer.super,
                                    .require_dhe_on_psk = 1};
    quic_ctx = quicly_spec_context;
    quic_ctx.tls = &tlsctx;
    quic_ctx.transport_params.max_streams_bidi = 10;
    quic_ctx.stream_open = &stream_open;
    quic_ctx.now = &get_now;

    fake_address.sa.sa_family = AF_INET;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Explicitly load the legacy provider in addition to default, as we test Blowfish in one of the tests. */
    (void)OSSL_PROVIDER_load(NULL, "legacy");
    (void)OSSL_PROVIDER_load(NULL, "default");
#endif

    {
        static const uint8_t key[PTLS_AES128_KEY_SIZE] = {0}, iv[PTLS_AES_IV_SIZE] = {0};
        test_random_cipher = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, key);
        assert(test_random_cipher != NULL);
        ptls_cipher_init(test_random_cipher, iv);
    }

    {
        BIO *bio = BIO_new_mem_buf(RSA_CERTIFICATE, strlen(RSA_CERTIFICATE));
        X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        assert(x509 != NULL || !!"failed to load certificate");
        BIO_free(bio);
        cert.len = i2d_X509(x509, &cert.base);
        X509_free(x509);
    }

    {
        BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, strlen(RSA_PRIVATE_KEY));
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        assert(pkey != NULL || !"failed to load private key");
        BIO_free(bio);
        ptls_openssl_init_sign_certificate(&cert_signer, pkey);
        EVP_PKEY_free(pkey);
    }

    quicly_amend_ptls_context(quic_ctx.tls);

    subtest("error-codes", test_error_codes);
    subtest("select_with_ratio255", test_select_with_ratio255);
    subtest("next-packet-number", test_next_packet_number);
    subtest("address-token-codec", test_address_token_codec);
    subtest("bplus_ranges", test_bplus_ranges);
    subtest("ranges", test_ranges);
    subtest("rate", test_rate);
    subtest("record-receipt", test_record_receipt);
    subtest("is-duplicate-pn", test_is_duplicate_pn);
    subtest("record-pn", test_record_pn);
    subtest("frame", test_frame);
    subtest("maxsender", test_maxsender);
    subtest("pacer", test_pacer);
    subtest("sentmap", test_sentmap);
    subtest("path-sentmap", test_path_sentmap);
    subtest("loss", test_loss);
    subtest("adjust-stream-frame-layout", test_adjust_stream_frame_layout);
    subtest("adjust-crypto-frame-layout", test_adjust_crypto_frame_layout);
    subtest("test-vector", test_vector);
    subtest("test-retry-aead", test_retry_aead);
    subtest("transport-parameters", test_transport_parameters);
    subtest("multipath-nonce", test_multipath_nonce);
    subtest("cid", test_cid);
    subtest("rotate-local-cids", test_rotate_local_cids);
    subtest("simple", test_simple);
    subtest("datagram-queue", test_datagram_queue);
    subtest("datagram-congestion", test_datagram_congestion);
    subtest("stream-concurrency", test_stream_concurrency);
    subtest("lossy", test_lossy_isolated);
    subtest("test-nondecryptable-initial", test_nondecryptable_initial);
    subtest("set_cc", test_set_cc);
    subtest("egress-selection", test_egress_selection);
    subtest("cc-accel-context", test_cc_accel_context);
    subtest("ecn-index-from-bits", test_ecn_index_from_bits);
    subtest("l4s-context", test_l4s_context);
    subtest("l4s-feedback", test_l4s_feedback);
    subtest("l4s-transfer", test_l4s_transfer);
    subtest("resume-sendrate", test_resume_sendrate);
    subtest("jumpstart-cwnd", test_jumpstart_cwnd);
    subtest("jumpstart", test_jumpstart);
    subtest("ack-for-unsent-pn", test_ack_for_unsent_pn);
    subtest("datagram-frame-amplification-limit", test_datagram_frame_amplification_limit);
    subtest("datagram-frame-max-size", test_datagram_frame_max_size);
    subtest("frames-for-unopened-local-stream", test_frames_for_unopened_local_stream);
    subtest("frames-opening-peer-stream", test_frames_opening_peer_stream);
    subtest("ack-frequency", test_ack_frequency);
    subtest("cc", test_cc);
    subtest("cc-limited-drain-and-resume", test_cc_limited_drain_and_resume);
    subtest("fractional-rtt-measurement", test_fractional_rtt_measurement);
    subtest("fractional-close-timeout", test_fractional_close_timeout);
    subtest("time-threshold-loss-episode", test_time_threshold_loss_episode);
    subtest("time-threshold-loss-in-recovery", test_time_threshold_loss_in_recovery);

    subtest("retransmit", test_retransmit);
    subtest("send-resumption-token-without-generator", test_send_resumption_token_without_generator);
    subtest("retransmit-max-stream-data-lower-window", test_retransmit_max_stream_data_lower_window);
    subtest("stream-credit-growth", test_stream_credit_growth);
    subtest("data-credit-growth", test_data_credit_growth);
    subtest("reset-stream-overflow-connection", test_reset_stream_overflow_connection);
    subtest("reset-stream-at-accounting", test_reset_stream_at_accounting);
    subtest("reset-stream-at-repeated", test_reset_stream_at_repeated, 0);
    subtest("reset-stream-at-repeated-data-above", test_reset_stream_at_repeated, 1);
    subtest("reset-stream-at-gap-after-reset", test_reset_stream_at_gap_after_reset);
    subtest("reset-stream-at-data-above", test_reset_stream_at_data_above);
    subtest("reset-stream-at-gap-above", test_reset_stream_at_gap_above);
    subtest("reset-stream-at-after-fin", test_reset_stream_at_after_fin);
    subtest("fin-below-received", test_fin_below_received);
    subtest("ingress-credit-exhaustive", test_ingress_credit_exhaustive);
    subtest("reset-stream-at-completing", test_reset_completing_transfer, 3, 1, 0);
    subtest("reset-stream-at-zero-completing", test_reset_completing_transfer, 0, 1, 0);
    subtest("reset-stream-completing", test_reset_completing_transfer, 0, 0, 0);
    subtest("reset-stream-at-zero-completing-null-cb", test_reset_completing_transfer, 0, 1, 1);
    subtest("reset-stream-completing-null-cb", test_reset_completing_transfer, 0, 0, 1);
    subtest("stop-sending-after-reset", test_stop_sending_after_reset, 1);
    subtest("stop-sending-repeated", test_stop_sending_after_reset, 0);
    subtest("reset-in-on-send-emit", test_reset_in_on_send_emit);
    subtest("stop-sending-before-fin", test_stop_sending_after_fin, QUICLY_SENDSTATE_EOS_STATE_UNSENT);
    subtest("stop-sending-after-fin", test_stop_sending_after_fin, QUICLY_SENDSTATE_EOS_STATE_INFLIGHT);
    subtest("stop-sending-after-fin-acked", test_stop_sending_after_fin, QUICLY_SENDSTATE_EOS_STATE_DELIVERED);
    subtest("destroy-returns-credit-fin", test_destroy_returns_credit_fin);
    subtest("destroy-returns-credit-reset", test_destroy_returns_credit_reset);
    subtest("stream-open-refused", test_stream_open_refused);
    subtest("lower-receive-window", test_lower_receive_window);
    subtest("state-exhaustion", test_state_exhaustion);
    subtest("amplification-blocked-handshake-timeout", test_amplification_blocked_handshake_timeout);
    subtest("migration-during-handshake", test_migration_during_handshake);
    subtest("pto-with-backup-path-probe", test_pto_with_backup_path_probe);

    subtest("multipath-negotiation", test_multipath_negotiation);
    subtest("multipath-state-isolation", test_multipath_state_isolation);
    subtest("multipath-lifecycle", test_multipath_lifecycle);
    subtest("multipath-scheduling", test_multipath_scheduling);
    subtest("multipath-custom-recovery", test_multipath_custom_recovery);

    subtest("stats-foreach", test_stats_foreach);

    ptls_cipher_free(test_random_cipher);
    ptls_openssl_dispose_sign_certificate(&cert_signer);
    OPENSSL_free(cert.base);
    return done_testing();
}
