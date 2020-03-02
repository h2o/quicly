#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/frame.h"

void __sanitizer_cov_trace_pc(void)
{
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	ptls_buffer_t buf;

	input = (quicly_address_token_plaintext_t){1, 234};
	input.remote.sin.sin_family = AF_INET;
	input.remote.sin.sin_addr.s_addr = htonl(0x7f000001);
	input.remote.sin.sin_port = htons(443);
	set_cid(&input.retry.odcid, ptls_iovec_init("abcdefgh", 8));
	input.retry.cidpair_hash = 12345;
	strcpy((char *)input.appdata.bytes, Data);
	input.appdata.len = Size;
	ptls_buffer_init(&buf, "", 0);
	quicly_encrypt_address_token(ptls_openssl_random_bytes, enc, &buf, 0, &input)	
}
