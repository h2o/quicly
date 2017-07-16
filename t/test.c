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
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "../lib/quicly.c"
#include "picotest.h"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEowIBAAKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6\n"                                                           \
    "A/Z+bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9\n"                                                           \
    "C7WcNcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7\n"                                                           \
    "ntPW/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDy\n"                                                           \
    "OxiNkLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MI\n"                                                           \
    "uDo7Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABAoIBAQCWcUv1wjR/2+Nw\n"                                                           \
    "B+Swp267R9bt8pdxyK6f5yKrskGErremiFygMrFtVBQYjws9CsRjISehSkN4GqjE\n"                                                           \
    "CweygJZVJeL++YvUmQnvFJSzgCjXU6GEStbOKD/A7T5sa0fmzMhOE907V+kpAT3x\n"                                                           \
    "E1rNRaP/ImJ1X1GjuefVb0rOPiK/dehFQWfsUkOvh+J3PU76wcnexxzJgxhVxdfX\n"                                                           \
    "qNa7UDsWzTImUjcHIfnhXc1K/oSKk6HjImQi/oE4lgoJUCEDaUbq0nXNrM0EmTTv\n"                                                           \
    "OQ5TVP5Lds9p8UDEa55eZllGXam0zKjhDKtkQ/5UfnxsAv2adY5cuH+XN0ExfKD8\n"                                                           \
    "wIZ5qINtAoGBAPRbQGZZkP/HOYA4YZ9HYAUQwFS9IZrQ8Y7C/UbL01Xli13nKalH\n"                                                           \
    "xXdG6Zv6Yv0FCJKA3N945lEof9rwriwhuZbyrA1TcKok/s7HR8Bhcsm2DzRD5OiC\n"                                                           \
    "3HK+Xy+6fBaMebffqBPp3Lfj/lSPNt0w/8DdrKBTw/cAy40g0n1zEu07AoGBAPHJ\n"                                                           \
    "V4IfQBiblCqDh77FfQRUNR4hVbbl00Gviigiw563nk7sxdrOJ1edTyTOUBHtM3zg\n"                                                           \
    "AT9sYz2CUXvsyEPqzMDANWMb9e2R//NcP6aM4k7WQRnwkZkp0WOIH95U2o1MHCYc\n"                                                           \
    "5meAHVf2UMl+64xU2ZfY3rjMmPLjWMt0hKYsOmtvAoGAClIQVkJSLXtsok2/Ucrh\n"                                                           \
    "81TRysJyOOe6TB1QNT1Gn8oiKMUqrUuqu27zTvM0WxtrUUTAD3A7yhG71LN1p8eE\n"                                                           \
    "3ytAuQ9dItKNMI6aKTX0czCNU9fKQ0fDp9UCkDGALDOisHFx1+V4vQuUIl4qIw1+\n"                                                           \
    "v9adA+iFzljqP/uy6DmEAyECgYAyWCgecf9YoFxzlbuYH2rukdIVmf9M/AHG9ZQg\n"                                                           \
    "00xEKhuOd4KjErXiamDmWwcVFHzaDZJ08E6hqhbpZN42Nhe4Ms1q+5FzjCjtNVIT\n"                                                           \
    "jdY5cCdSDWNjru9oeBmao7R2I1jhHrdi6awyeplLu1+0cp50HbYSaJeYS3pbssFE\n"                                                           \
    "EIWBhQKBgG3xleD4Sg9rG2OWQz5IrvLFg/Hy7YWyushVez61kZeLDnt9iM2um76k\n"                                                           \
    "/xFNIW0a+eL2VxRTCbXr9z86hjc/6CeSJHKYFQl4zsSAZkaIJ0+HbrhDNBAYh9b2\n"                                                           \
    "mRdX+OMdZ7Z5J3Glt8ENFRqe8RlESMpAKxjR+dID0bjwAjVr2KCh\n"                                                                       \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIICqDCCAZACCQDI5jeEvExN+TANBgkqhkiG9w0BAQUFADAWMRQwEgYDVQQDEwtl\n"                                                           \
    "eGFtcGxlLmNvbTAeFw0xNjA5MzAwMzQ0NTFaFw0yNjA5MjgwMzQ0NTFaMBYxFDAS\n"                                                           \
    "BgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"                                                           \
    "AQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+bViFlfEg\n"                                                           \
    "L37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7WcNcshpSdm\n"                                                           \
    "2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW/XCchVf+\n"                                                           \
    "ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiNkLFLvUdT\n"                                                           \
    "4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7Vhkq5+TC\n"                                                           \
    "qXsIFNbjy0taOoPRvUbPsbqFlQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAwZQsG\n"                                                           \
    "E/3DQFBOnmBITFsaIVJVXU0fbfIjy3p1r6O9z2zvrfB1i8AMxOORAVjE5wHstGnK\n"                                                           \
    "3sLMjkMYXqu1XEfQbStQN+Bsi8m+nE/x9MmuLthpzJHXUmPYZ4TKs0KJmFPLTXYi\n"                                                           \
    "j0OrP0a5BNcyGj/B4Z33aaU9N3z0TWBwx4OPjJoK3iInBx80sC1Ig2PE6mDBxLOg\n"                                                           \
    "5Ohm/XU/43MrtH8SgYkxr3OyzXTm8J0RFMWhYlo1uqR+pWV3TgacixNnUq5w5h4m\n"                                                           \
    "sqXcikh+j8ReNXsKnMOAfFo+HbRqyKWNE3DekCIiiQ5ds4A4SfT7pYyGAmBkAxht\n"                                                           \
    "sS919x2o8l97kaYf\n"                                                                                                           \
    "-----END CERTIFICATE-----\n"

static int on_stream_open(quicly_context_t *ctx, quicly_conn_t *conn, quicly_stream_t *stream);

static ptls_iovec_t cert;
static ptls_openssl_sign_certificate_t cert_signer;
static ptls_context_t tls_ctx = {
    ptls_openssl_random_bytes, ptls_openssl_key_exchanges, ptls_openssl_cipher_suites, {&cert, 1}, NULL, NULL, &cert_signer.super};
static quicly_context_t quic_ctx = {
    &tls_ctx, 1280, {8192, 64, 100, 60, 0}, quicly_default_alloc_packet, quicly_default_free_packet, on_stream_open};

static void test_acker(void)
{
    struct st_quicly_acker_t acker;
    int ret;

    memset(&acker, 0, sizeof(acker));

    ret = acker_record(&acker, 333);
    ok(ret == 0);
    ok(acker.num_blocks == 1);
    ok(acker.blocks[0].start == 333);
    ok(acker.blocks[0].end == 334);

    ret = acker_record(&acker, 334);
    ok(ret == 0);
    ok(acker.num_blocks == 1);
    ok(acker.blocks[0].start == 333);
    ok(acker.blocks[0].end == 335);

    ret = acker_record(&acker, 337);
    ok(ret == 0);
    ok(acker.num_blocks == 2);
    ok(acker.blocks[0].start == 333);
    ok(acker.blocks[0].end == 335);
    ok(acker.blocks[1].start == 337);
    ok(acker.blocks[1].end == 338);

    ret = acker_record(&acker, 336);
    ok(ret == 0);
    ok(acker.num_blocks == 2);
    ok(acker.blocks[0].start == 333);
    ok(acker.blocks[0].end == 335);
    ok(acker.blocks[1].start == 336);
    ok(acker.blocks[1].end == 338);

    ret = acker_record(&acker, 335);
    ok(ret == 0);
    ok(acker.num_blocks == 1);
    ok(acker.blocks[0].start == 333);
    ok(acker.blocks[0].end == 338);
}

static void free_packets(quicly_raw_packet_t **packets, size_t cnt)
{
    size_t i;
    for (i = 0; i != cnt; ++i)
        quicly_default_free_packet(&quic_ctx, packets[i]);
}

static void decode_packets(quicly_decoded_packet_t *decoded, quicly_raw_packet_t **raw, size_t cnt)
{
    size_t i;
    for (i = 0; i != cnt; ++i) {
        int ret = quicly_decode_packet(decoded + i, raw[i]->data.base, raw[i]->data.len);
        ok(ret == 0);
    }
}

static int send_data(quicly_stream_t *stream, const char *s)
{
    return quicly_write_stream(stream, s, strlen(s), 1);
}

static int on_req_receive(quicly_conn_t *conn, quicly_stream_t *stream, ptls_iovec_t *vec, size_t count, int is_fin)
{
    if (is_fin)
        return send_data(stream, "HTTP/1.0 200 OK\r\n\r\nhello world\n");
    return 0;
}

static int on_stream_open(quicly_context_t *ctx, quicly_conn_t *conn, quicly_stream_t *stream)
{
    stream->on_receive = on_req_receive;
    return 0;
}

static int on_resp_receive(quicly_conn_t *conn, quicly_stream_t *stream, ptls_iovec_t *vec, size_t count, int is_fin)
{
    size_t i;

    for (i = 0; i != count; ++i)
        fwrite(vec[0].base, 1, vec[0].len, stderr);

    if (is_fin) {
        done_testing();
        exit(0);
    }

    return 0;
}

static void test_mozquic(void)
{
    struct st_quicly_decoded_frame_t frame;
    static const char *mess = "\xc5\0\0\0\0\0\0\xb6\x16\x03";
    static const uint8_t *p;
    p = mess;
    decode_frame(&frame, &p, p + 10);
}

int main(int argc, char **argv)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    subtest("mozquic", test_mozquic);
    subtest("acker", test_acker);

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

    quicly_conn_t *client, *server;
    static quicly_stream_t *client_stream;
    quicly_raw_packet_t *packets[32];
    size_t num_packets;
    quicly_decoded_packet_t decoded[32];
    int ret, i;

    /* send CH */
    ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
    ok(ret == 0);
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(client, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets == 1);
    ok(packets[0]->data.len == 1280);

    /* receive CH, send handshake upto ServerFinished */
    decode_packets(decoded, packets, num_packets);
    ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, decoded);
    ok(ret == 0);
    free_packets(packets, num_packets);
    ok(quicly_get_state(server) == QUICLY_STATE_1RTT_ENCRYPTED);
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(server, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive ServerFinished */
    decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_packets; ++i) {
        ret = quicly_receive(client, decoded + i);
        ok(ret == 0);
    }
    free_packets(packets, num_packets);
    ok(quicly_get_state(client) == QUICLY_STATE_1RTT_ENCRYPTED);

    /* enqueue HTTP request */
    ret = quicly_open_stream(client, &client_stream);
    ok(ret == 0);
    client_stream->on_receive = on_resp_receive;
    ret = send_data(client_stream, "GET / HTTP/1.0\r\n\r\n");
    ok(ret == 0);

    /* send ClientFinished and the request */
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(client, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets != 0);

    /* recieve ClientFinish and request */
    decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_packets; ++i) {
        ret = quicly_receive(server, decoded + i);
        ok(ret == 0);
    }
    free_packets(packets, num_packets);

    /* send response */
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(server, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive response */
    decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_packets; ++i) {
        ret = quicly_receive(client, decoded + i);
        ok(ret == 0);
    }

    ok(!"unreachable");

    return 111;
}
