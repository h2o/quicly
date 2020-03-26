#include <picotls.h>
#include <stdio.h>
#include <netdb.h>
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/frame.h"
#include "../deps/picotls/include/picotls/openssl.h"

void __sanitizer_cov_trace_pc(void)
{
}

static struct {
    ptls_iovec_t tls_ticket;
    ptls_iovec_t address_token;
} session_info;

int save_session_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src)
{
    return 0; 
}

static int on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    return 0;
}

static ptls_key_exchange_algorithm_t *key_exchanges[128];
static ptls_cipher_suite_t *cipher_suites[128];

static ptls_save_ticket_t save_session_ticket = {save_session_ticket_cb};
static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};

static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                .get_time = &ptls_get_time,
                                .key_exchanges = key_exchanges,
                                .cipher_suites = ptls_openssl_cipher_suites,
                                .require_dhe_on_psk = 1 , 
                                .save_ticket = &save_session_ticket,
                                .on_client_hello = &on_client_hello};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	int ret;
	quicly_context_t ctx;
	ctx = quicly_spec_context;
	ctx.tls = &tlsctx;

	quicly_decoded_packet_t p;

	struct sockaddr sa;
	socklen_t salen;
		
	quicly_conn_t *conn = NULL;
	quicly_cid_plaintext_t next_cid;
	const char* host = "127.0.0.1";
	const char* port = "4422";
	ptls_iovec_t *resumption_token = (ptls_iovec_t *)malloc(sizeof(ptls_iovec_t));
	ptls_handshake_properties_t hs_properties;
	quicly_transport_parameters_t resumed_transport_params;

	struct addrinfo hint, *res;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_protocol = IPPROTO_UDP;
	hint.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
	getaddrinfo(host, port, &hint, &res);

	memcpy(&sa, res->ai_addr, res->ai_addrlen);
	
	resumption_token->len = 0;

	ret = quicly_connect(&conn, &ctx, host, &sa, NULL, &next_cid, *resumption_token, &hs_properties, &resumed_transport_params);

	ret = quicly_decode_packet(&ctx, &p, Data, Size);

	if (ret != Size)
		return 0;

	quicly_receive(conn, NULL, &sa, &p);
   		
	return 0;
}
