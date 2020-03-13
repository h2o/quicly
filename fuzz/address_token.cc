#include <string.h>
#include <stdio.h>
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
        char b[3];
	ptls_aead_context_t *enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, zero_key, "");
	ptls_buffer_init(&buf, b, 0);

	quicly_encrypt_address_token(ptls_openssl_random_bytes, enc, &buf, Size, (quicly_address_token_plaintext_t *)Data);	
}
