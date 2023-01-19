#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#include "quicly.h"
#include "quicly/streambuf.h"

#define MAX_BURST_PACKETS 10

static const unsigned verbosity = 0;
static int suppress_output = 0;
static int64_t enqueue_requests_at = 0;
static int send_datagram_frame = 0;

static void hexdump(const char *title, const uint8_t *p, size_t l)
{
    fprintf(stderr, "%s (%zu bytes):\n", title, l);

    while (l != 0) {
        int i;
        fputs("   ", stderr);
        for (i = 0; i < 16; ++i) {
            fprintf(stderr, " %02x", *p++);
            if (--l == 0)
                break;
        }
        fputc('\n', stderr);
    }
}

static struct {
    ptls_iovec_t config_list;
    struct {
        struct {
            ptls_hpke_kem_t *kem;
            ptls_key_exchange_context_t *ctx;
        } list[16];
        size_t count;
    } keyex;
    struct {
        ptls_iovec_t configs;
        char *fn;
    } retry;
} ech;

static void ech_save_retry_configs(void)
{
    if (ech.retry.configs.base == NULL)
        return;

    FILE *fp;
    if ((fp = fopen(ech.retry.fn, "wt")) == NULL) {
        fprintf(stderr, "failed to write to ECH config file:%s:%d\n", ech.retry.fn, errno);
        exit(1);
    }
    fwrite(ech.retry.configs.base, 1, ech.retry.configs.len, fp);
    fclose(fp);
}

static void send_str(quicly_stream_t *stream, const char *s)
{
    quicly_streambuf_egress_write(stream, s, strlen(s));
}

/**
 * list of requests to be processed, terminated by reqs[N].path == NULL
 */
struct {
    const char *path;
    int to_file;
} *reqs;

struct st_stream_data_t {
    quicly_streambuf_t streambuf;
    FILE *outfp;
};

static void enqueue_requests(quicly_conn_t *conn)
{
    size_t i;
    int ret;

    for (i = 0; reqs[i].path != NULL; ++i) {
        char req[1024], destfile[1024];
        quicly_stream_t *stream;
        ret = quicly_open_stream(conn, &stream, 0);
        assert(ret == 0);
        sprintf(req, "GET %s\r\n", reqs[i].path);
        send_str(stream, req);
        quicly_streambuf_egress_shutdown(stream);

        if (reqs[i].to_file && !suppress_output) {
            struct st_stream_data_t *stream_data = stream->data;
            sprintf(destfile, "%s.downloaded", strrchr(reqs[i].path, '/') + 1);
            stream_data->outfp = fopen(destfile, "w");
            if (stream_data->outfp == NULL) {
                fprintf(stderr, "failed to open destination file:%s:%d\n", reqs[i].path, errno);
                exit(1);
            }
        }
    }
    enqueue_requests_at = INT64_MAX;
}

static void send_packets_default(int fd, struct sockaddr *dest, struct iovec *packets, size_t num_packets)
{
    for (size_t i = 0; i != num_packets; ++i) {
        struct msghdr mess;
        memset(&mess, 0, sizeof(mess));
        mess.msg_name = dest;
        mess.msg_namelen = quicly_get_socklen(dest);
        mess.msg_iov = &packets[i];
        mess.msg_iovlen = 1;
        if (verbosity >= 2)
            hexdump("sendmsg", packets[i].iov_base, packets[i].iov_len);
        int ret;
        while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
            ;
        // if (ret == -1)
            puts("sendmsg failed");
    }
}

static void (*send_packets)(int, struct sockaddr *, struct iovec *, size_t) = send_packets_default;

static int send_pending(int fd, quicly_conn_t *conn)
{
    quicly_address_t dest, src;
    struct iovec packets[MAX_BURST_PACKETS];
    uint8_t buf[MAX_BURST_PACKETS * quicly_get_context(conn)->transport_params.max_udp_payload_size];
    size_t num_packets = MAX_BURST_PACKETS;
    int ret;

    if ((ret = quicly_send(conn, &dest, &src, packets, &num_packets, buf, sizeof(buf))) == 0 && num_packets != 0)
        send_packets(fd, &dest.sa, packets, num_packets);

    return ret;
}

static int run_client(int fd, struct sockaddr *sa, const char *host)
{
    quicly_context_t ctx;
    quicly_cid_plaintext_t next_cid;
    ptls_iovec_t resumption_token;
    ptls_handshake_properties_t hs_properties;
    quicly_transport_parameters_t resumed_transport_params;

    struct sockaddr_in local;
    int ret;
    quicly_conn_t *conn = NULL;

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    if (bind(fd, (void *)&local, sizeof(local)) != 0) {
        puts("bind(2) failed");
        return 1;
    }
    ret = quicly_connect(&conn, &ctx, host, sa, NULL, &next_cid, resumption_token, &hs_properties, &resumed_transport_params);
    assert(ret == 0);
    ++next_cid.master_id;
    enqueue_requests(conn);
    send_pending(fd, conn);

    while (1) {
        fd_set readfds;
        struct timeval *tv, tvbuf;
        do {
            int64_t timeout_at = conn != NULL ? quicly_get_first_timeout(conn) : INT64_MAX;
            if (enqueue_requests_at < timeout_at)
                timeout_at = enqueue_requests_at;
            if (timeout_at != INT64_MAX) {
                quicly_context_t *ctx = quicly_get_context(conn);
                int64_t delta = timeout_at - ctx->now->cb(ctx->now);
                if (delta > 0) {
                    tvbuf.tv_sec = delta / 1000;
                    tvbuf.tv_usec = (delta % 1000) * 1000;
                } else {
                    tvbuf.tv_sec = 0;
                    tvbuf.tv_usec = 0;
                }
                tv = &tvbuf;
            } else {
                tv = NULL;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, tv) == -1 && errno == EINTR);
        if (enqueue_requests_at <= ctx.now->cb(ctx.now))
            enqueue_requests(conn);
        if (FD_ISSET(fd, &readfds)) {
            while (1) {
                uint8_t buf[ctx.transport_params.max_udp_payload_size];
                struct msghdr mess;
                struct sockaddr sa;
                struct iovec vec;
                memset(&mess, 0, sizeof(mess));
                mess.msg_name = &sa;
                mess.msg_namelen = sizeof(sa);
                vec.iov_base = buf;
                vec.iov_len = sizeof(buf);
                mess.msg_iov = &vec;
                mess.msg_iovlen = 1;
                ssize_t rret;
                while ((rret = recvmsg(fd, &mess, 0)) == -1 && errno == EINTR)
                    ;
                if (rret <= 0)
                    break;
                if (verbosity >= 2)
                    hexdump("recvmsg", buf, rret);
                size_t off = 0;
                while (off != rret) {
                    quicly_decoded_packet_t packet;
                    if (quicly_decode_packet(&ctx, &packet, buf, rret, &off) == SIZE_MAX)
                        break;
                    quicly_receive(conn, NULL, &sa, &packet);
                    if (send_datagram_frame && quicly_connection_is_ready(conn)) {
                        const char *message = "hello datagram!";
                        ptls_iovec_t datagram = ptls_iovec_init(message, strlen(message));
                        quicly_send_datagram_frames(conn, &datagram, 1);
                        send_datagram_frame = 0;
                    }
                }
            }
        }
        if (conn != NULL) {
            ret = send_pending(fd, conn);
            if (ret != 0) {
                ech_save_retry_configs();
                quicly_free(conn);
                conn = NULL;
                if (ret == QUICLY_ERROR_FREE_CONNECTION) {
                    return 0;
                } else {
                    fprintf(stderr, "quicly_send returned %d\n", ret);
                    return 1;
                }
            }
        }
    }
}

static inline int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
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
        fprintf(stderr, "failed to resolve address:%s:%s:%d\n", host, port, err);
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

int quic_transaction(void)
{
    struct sockaddr_storage sa;
    socklen_t salen;
    const char host[] = "quant.eggert.org";
    const char port[] = "4433";
    int fd;

    if (resolve_address((void *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
        exit(1);

    if ((fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        puts("socket(2) failed");
        return 1;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);

    return run_client(fd, (void *)&sa, host);
}
