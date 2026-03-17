#include "quic_retry.h"
#include "quic_types.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct {
    const uint8_t *key;
    const uint8_t *nonce;
} quic_retry_secret_t;

static const uint8_t quic_retry_key_v1[16] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};

static const uint8_t quic_retry_nonce_v1[12] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb
};

static const uint8_t quic_retry_key_v2[16] = {
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
};

static const uint8_t quic_retry_nonce_v2[12] = {
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
    0x90, 0xef, 0xb0, 0x4a
};

static const quic_retry_secret_t *quic_retry_secret_for_version(uint32_t version) {
    static const quic_retry_secret_t v1 = { quic_retry_key_v1, quic_retry_nonce_v1 };
    static const quic_retry_secret_t v2 = { quic_retry_key_v2, quic_retry_nonce_v2 };

    if (version == QUIC_V1_VERSION) {
        return &v1;
    }
    if (version == QUIC_V2_VERSION) {
        return &v2;
    }
    return NULL;
}

int quic_retry_compute_integrity_tag(
    uint32_t version,
    const quic_cid_t *original_dcid,
    const uint8_t *retry_without_tag,
    size_t retry_without_tag_len,
    uint8_t out_tag[QUIC_RETRY_INTEGRITY_TAG_LEN]
) {
    const quic_retry_secret_t *secret;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t pseudo_packet[1 + MAX_CID_LEN + 2048];
    size_t pseudo_len;
    int out_len = 0;
    int ok = -1;

    if (!original_dcid || !retry_without_tag || !out_tag || original_dcid->len > MAX_CID_LEN) {
        return -1;
    }
    if (retry_without_tag_len > 2048) {
        return -1;
    }

    secret = quic_retry_secret_for_version(version);
    if (!secret) {
        return -1;
    }

    pseudo_packet[0] = original_dcid->len;
    memcpy(pseudo_packet + 1, original_dcid->data, original_dcid->len);
    memcpy(pseudo_packet + 1 + original_dcid->len, retry_without_tag, retry_without_tag_len);
    pseudo_len = 1 + original_dcid->len + retry_without_tag_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, secret->key, secret->nonce) != 1) goto cleanup;
    if (EVP_EncryptUpdate(ctx, NULL, &out_len, pseudo_packet, (int)pseudo_len) != 1) goto cleanup;
    if (EVP_EncryptFinal_ex(ctx, NULL, &out_len) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QUIC_RETRY_INTEGRITY_TAG_LEN, out_tag) != 1) goto cleanup;

    ok = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int quic_retry_verify_integrity_tag(
    uint32_t version,
    const quic_cid_t *original_dcid,
    const uint8_t *retry_packet,
    size_t retry_packet_len
) {
    uint8_t expected_tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
    if (!retry_packet || retry_packet_len < QUIC_RETRY_INTEGRITY_TAG_LEN) {
        return -1;
    }
    if (quic_retry_compute_integrity_tag(version, original_dcid,
                                         retry_packet,
                                         retry_packet_len - QUIC_RETRY_INTEGRITY_TAG_LEN,
                                         expected_tag) != 0) {
        return -1;
    }
    return CRYPTO_memcmp(expected_tag,
                         retry_packet + retry_packet_len - QUIC_RETRY_INTEGRITY_TAG_LEN,
                         QUIC_RETRY_INTEGRITY_TAG_LEN) == 0 ? 0 : -1;
}
