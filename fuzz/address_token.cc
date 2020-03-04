#include "address_token.h"
#include <string.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

void __sanitizer_cov_trace_pc(void)
{
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static const uint8_t zero_key[PTLS_MAX_SECRET_SIZE] = {0};
	ptls_buffer_t buf;
        quicly_address_token_plaintext_t input;
	ptls_aead_context_t *enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, zero_key, "");

	input = (quicly_address_token_plaintext_t){1, 234};
	input.remote.sin.sin_family = AF_INET;
	input.remote.sin.sin_addr.s_addr = htonl(0x7f000001);
	input.remote.sin.sin_port = htons(443);
	set_cid(&input.retry.odcid, ptls_iovec_init("abcdefgh", 8));
	input.retry.cidpair_hash = 12345;
	strcpy((char *)input.appdata.bytes, (char *)Data);
	input.appdata.len = Size;
	ptls_buffer_init(&buf, "", 0);
	quicly_encrypt_address_token(ptls_openssl_random_bytes, enc, &buf, 0, &input);	
}
