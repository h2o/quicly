#pragma once

#if defined(_WIN32)
    #include <Winsock2.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/udp.h>
    #include <netdb.h>
    #include <sys/time.h>
    #include <pthread.h>
#endif

#include "quicly/constants.h"

// WIN32 redundant?
#if defined(_WINDOWS) || defined(WIN32)
# define __thread __declspec(thread)

struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

#ifdef __GNUC__
#define clz(x) __builtin_clz(x)
#define clzll(x) __builtin_clzll(x)
#define popcountl(x) __builtin_popcountl(x)
#else
inline int clz(uint32_t x) {
    unsigned long r = 0;
    _BitScanReverse(&r, x);
    return 31 ^ (int)(r);
}

inline int clzll(uint64_t x) {
    unsigned long r = 0;
#  ifdef _WIN64
    _BitScanReverse64(&r, x);
#  else
    // Scan the high 32 bits.
    if (_BitScanReverse(&r, (uint32_t)(x >> 32))) return 63 ^ (r + 32);
    // Scan the low 32 bits.
    _BitScanReverse(&r, (uint32_t)(x));
#  endif
    return 63 ^ (int)(r);
}

static inline int popcountl(uint64_t x)
{
    // See https://en.wikipedia.org/wiki/Hamming_weight.
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    return (x * 0x01010101) >> 24;
}
#endif

#ifndef IPTOS_ECN_CE
# define	IPTOS_ECN_CE		0x03
#endif
