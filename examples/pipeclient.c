/*
 * Copyright (c) 2021 Jordi Cenzano
 * Created from ./echo.c
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

/**
 * the QUIC context
 */
static quicly_context_t ctx;
/**
 * CID seed
 */
static quicly_cid_plaintext_t next_cid;
/**
 * Verbose mode
 */
 int is_verbose = 0;

static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
                           int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static void usage(const char *progname)
{
    printf("Usage: %s [options] [host]\n"
           "Options:\n"
           "  -v Show messages from server"
           "  -p <number>  specifies the port number (default: 4433)\n"
           "  -h           prints this help\n"
           "\n"
           "If omitted, host defaults to 127.0.0.1.\n"
           "\n"
           "Example (sends live video over QUIC):\n"
           "ffmpeg -i \"udp://localhost:5000\" -c copy -f mpegts - | %s -p 4433 localhost\n",
           progname, progname);
    exit(0);
}

static int forward_stdin(quicly_conn_t *conn)
{
    quicly_stream_t *stream0;
    const size_t READ_BLOCK_SIZE = 188 * 6; // Assumed input is transport stream
    char buf[READ_BLOCK_SIZE];
    size_t rret;

    if ((stream0 = quicly_get_stream(conn, 0)) == NULL || !quicly_sendstate_is_open(&stream0->sendstate))
        return 0;

    /* Read binary from stdin */
    while ((rret = read(STDIN_FILENO, buf, READ_BLOCK_SIZE)) == -1 && errno == EINTR)
        ;

    fprintf(stderr, "Read from stdin: %zu bytes\n", rret);
    
    // Something wrong!
    if (rret < 0) {
        // Show error and close the stream
        fprintf(stderr, "failed to read from stdin");
        rret = 0;
    }

    if (rret == 0) {
        fprintf(stderr, "Closing\n");
        /* stdin closed, close the send-side of stream0 */
        quicly_streambuf_egress_shutdown(stream0);
        return 0;
    } else {
        /* write data to send buffer */
        quicly_streambuf_egress_write(stream0, buf, rret);
        return 1;
    }
}

static void on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    /* print to stdout any data re receive from server*/
    if (is_verbose) {
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);
    }
    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}

static void process_msg(quicly_conn_t *client, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;

        if (client != NULL) {
            if (quicly_is_destination(client, NULL, msg->msg_name, &decoded))
                quicly_receive(client, NULL, msg->msg_name, &decoded);
        }
    }
}

static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
{
    struct msghdr mess = {.msg_name = dest, .msg_namelen = quicly_get_socklen(dest), .msg_iov = vec, .msg_iovlen = 1};
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int run_loop_client(int fd, quicly_conn_t *client)
{
    int read_stdin = 1;

    while (1) {      
        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            int64_t first_timeout = INT64_MAX, now = ctx.now->cb(ctx.now);
            int64_t conn_timeout = quicly_get_first_timeout(client);
            if (conn_timeout < first_timeout)
                first_timeout = conn_timeout;
            if (now < first_timeout) {
                int64_t delta = first_timeout - now;
                if (delta > 1000 * 1000)
                    delta = 1000 * 1000;
                tv.tv_sec = delta / 1000;
                tv.tv_usec = (delta % 1000) * 1000;
            } else {
                tv.tv_sec = 1000;
                tv.tv_usec = 0;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
            if (read_stdin)
                FD_SET(STDIN_FILENO, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            if (rret > 0)
                process_msg(client, &msg, rret);
        }
    
        if (FD_ISSET(0, &readfds)) {
            assert(client != NULL);
            if (!forward_stdin(client))
                read_stdin = 0;
        }

        /* send QUIC packets, if any */
        quicly_address_t dest, src;
        struct iovec dgrams[10];
        uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
        size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
        int ret = quicly_send(client, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
        switch (ret) {
        case 0: {
            size_t j;
            for (j = 0; j != num_dgrams; ++j) {
                send_one(fd, &dest.sa, &dgrams[j]);
            }
        } break;
        case QUICLY_ERROR_FREE_CONNECTION:
            /* connection has been closed, free, and exit when running as a client */
            quicly_free(client);
            return 0;
        default:
            fprintf(stderr, "quicly_send returned %d\n", ret);
            return 1;
        }
    }

    return 0;
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}

int main(int argc, char **argv)
{
    ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "127.0.0.1", *port = "4433";
    struct sockaddr_storage sa;
    socklen_t salen;
    int ch, fd;

    /* setup quic context */
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;

    /* resolve command line options and arguments */
    while ((ch = getopt(argc, argv, "p:h:v")) != -1) {
        switch (ch) {
        case 'p': /* port */
            port = optarg;
            break;
        case 'v': /* verbose */
            is_verbose = 1;
            break;
        case 'h': /* help */
            usage(argv[0]);
            break;
        default:
            exit(1);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0)
        host = *argv++;
    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
        exit(1);

    /* open socket on any port (as a client) */
    if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket(2) failed");
        exit(1);
    }
    // fcntl(fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind(2) failed");
        exit(1);
    }

    quicly_conn_t *client = NULL;
    /* initiate a connection, and open a stream */
    int ret;
    if ((ret = quicly_connect(&client, &ctx, host, (struct sockaddr *)&sa, NULL, &next_cid, ptls_iovec_init(NULL, 0), NULL,
                                NULL)) != 0) {
        fprintf(stderr, "quicly_connect failed:%d\n", ret);
        exit(1);
    }
    quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
    quicly_open_stream(client, &stream, 0);

    /* enter the event loop with a connection object */
    return run_loop_client(fd, client);
}
