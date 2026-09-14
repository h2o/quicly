/*
 * Implementation notes (see usage() for the interface):
 *
 * Packet handling:
 *   Attach to the configured Linux TUN using TUNSETIFF with IFF_TUN | IFF_NO_PI.
 *   Discard packets whose source and destination ports both equal server-port, because their direction is ambiguous.
 *   Discard IPv4 fragments (MF set or nonzero fragment offset); noninitial fragments lack transport ports.
 *   To emulate one router hop, discard TTL <= 1; otherwise decrement TTL and update the IPv4 header checksum. The kernel's
 *   local-delivery path does not decrement TTL. The address swap preserves the IP and TCP/UDP pseudo-header sums, so
 *   transport checksums need no adjustment. With no link smaller than the fixed TUN MTU, no PMTUD handling is needed.
 *
 * Scheduling:
 *   Each direction has a propagation-delay stage followed by a shared FIFO bottleneck. Delay storage is separate from
 *   bottleneck capacity. Tail-drop arrivals when free buffer space is below one TUN MTU, regardless of packet size.
 *   An idle bottleneck emits immediately; emitting L IP bytes at
 *   rate w prevents another emission for L/w seconds. Do not accumulate transmission credit while idle. Use complete IP
 *   lengths for bandwidth and buffer accounting. Require nonnegative delay, positive rate, and buffers at least the TUN MTU.
 *
 * Event loop:
 *   Use one thread, nonblocking TUN I/O, CLOCK_MONOTONIC, and select() with a timeout to the earliest absolute deadline.
 *   Continue reading even when the bottleneck is full, dropping in userspace to avoid an unmodelled kernel queue. Process
 *   due events between bounded read batches so continuous arrivals cannot starve timers. Retry interrupted I/O. Use
 *   nonblocking TUN writes and drop on EAGAIN, without queueing for retry or monitoring write readiness.
 *
 * Statistics:
 *   Use the current monotonic time when reading or writing each packet.
 *   In the select() loop, emit an object for each completed millisecond, including empty milliseconds after a late wakeup.
 *   Port reuse shares a series; tunulator does not track TCP connection lifetimes or QUIC connections multiplexed on one socket.
 */
/*
 * Copyright (c) 2026 Kazuho Oku
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *cmd)
{
    printf("Usage: %s -t tun-file [options] peer-ip server-port\n"
           "       %s -h\n"
           "\n"
           "Emulate a network between local TCP/UDP endpoints through a single TUN.\n"
           "Swap IPv4 addresses between peer-ip and 127.0.0.1, preserving ports.\n"
           "\n"
           "Options:\n"
           "  -t <tun-file>       TUN device path (required; Linux: /dev/net/tun)\n"
           "  -n <interface>      preconfigured Linux TUN interface (default: tun0)\n"
           "  -b <bytes>          upstream FIFO capacity (default: 100000)\n"
           "  -B <bytes>          downstream FIFO capacity (default: 100000)\n"
           "  -w <bytes_per_sec>  upstream throughput (default: 4294967295, UINT32_MAX)\n"
           "  -W <bytes_per_sec>  downstream throughput (default: 4294967295, UINT32_MAX)\n"
           "  -p <microseconds>   upstream propagation delay (default: 0)\n"
           "  -P <microseconds>   downstream propagation delay (default: 0)\n"
           "  -h                  print this help and exit\n"
           "\n"
           "peer-ip is the virtual IPv4 peer; server-port is the local TCP/UDP port.\n"
           "Upstream means client-to-server; downstream means server-to-client.\n"
           "Directions have independent queues/rates; added base RTT is -p plus -P.\n"
           "\n"
           "Statistics: emit a JSON object containing only active flows each millisecond\n"
           "on stdout, followed by a newline:\n"
           "  {\"u12345\":[2400,1200,80,80],\"t12347\":[1200,1200,0,0]}\n"
           "Keys are u (UDP) or t (TCP) followed by the client port. Arrays contain\n"
           "[up_received, up_sent, down_received, down_sent]\n"
           "IP bytes for that millisecond. Received is before drops; sent is a\n"
           "successful TUN write.\n"
           "\n"
           "Setup: route peer-ip through TUN with source 127.0.0.1, enable Linux\n"
           "route_localnet, and configure a fixed MTU. Do not assign peer-ip locally.\n"
           "Disable TUN checksum/segmentation offload. Initially only unfragmented\n"
           "IPv4 TCP/UDP is planned; routing and interface setup are external.\n"
           "\n"
           "Example (DSL profile, with IP-byte accounting):\n"
           "  %s -t /dev/net/tun -n tun0 -p 30000 -w 3750000 -b 187500 1.2.3.4 4433\n",
           cmd, cmd, cmd);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }

    fprintf(stderr, "%s: forwarding is not implemented; use -h to view the proposed interface.\n", argv[0]);
    return EXIT_FAILURE;
}
