#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "quic_types.h"
#include "quic_version.h"
#include "quic_crypto.h"

void test_initial_key_derivation_rfc9369() {
    quic_cid_t dcid = { .len = 8, .data = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08} };
    const quic_version_ops_t *ops_v2 = quic_version_get_ops(QUIC_V2_VERSION);
    
    quic_crypto_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    int ret = quic_crypto_setup_initial_keys(&dcid, ops_v2, &ctx);
    assert(ret == 0);

    const uint8_t expected_client_secret[] = {
        0x14, 0xec, 0x9d, 0x6e, 0xb9, 0xfd, 0x7a, 0xf8, 0x3b, 0xf5, 0xa6, 0x68, 0xbc, 0x17, 0xa7, 0xe2,
        0x83, 0x76, 0x6a, 0xad, 0xe7, 0xec, 0xd0, 0x89, 0x1f, 0x70, 0xf9, 0xff, 0x7f, 0x4b, 0xf4, 0x7b
    };
    assert(memcmp(ctx.client_initial.secret, expected_client_secret, QUIC_MD_HASH_SIZE) == 0);

    const uint8_t expected_client_key[] = {
        0x8b, 0x1a, 0x0b, 0xc1, 0x21, 0x28, 0x42, 0x90, 0xa2, 0x9e, 0x09, 0x71, 0xb5, 0xcd, 0x04, 0x5d
    };
    assert(memcmp(ctx.client_initial.key, expected_client_key, QUIC_AEAD_KEY_SIZE) == 0);

    const uint8_t expected_client_iv[] = {
        0x91, 0xf7, 0x3e, 0x23, 0x51, 0xd8, 0xfa, 0x91, 0x66, 0x0e, 0x90, 0x9f
    };
    assert(memcmp(ctx.client_initial.iv, expected_client_iv, QUIC_AEAD_IV_SIZE) == 0);

    const uint8_t expected_client_hp[] = {
        0x45, 0xb9, 0x5e, 0x15, 0x23, 0x5d, 0x6f, 0x45, 0xa6, 0xb1, 0x9c, 0xbc, 0xb0, 0x29, 0x4b, 0xa9
    };
    assert(memcmp(ctx.client_initial.hp, expected_client_hp, QUIC_HP_KEY_SIZE) == 0);

    printf("[PASS] v2 Initial Key Derivation matches RFC 9369 perfectly\n");
}

int main() {
    test_initial_key_derivation_rfc9369();
    return 0;
}