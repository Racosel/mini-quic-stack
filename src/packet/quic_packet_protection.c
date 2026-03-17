#include "quic_packet_protection.h"
#include <openssl/evp.h>
#include <string.h>

static void quic_build_nonce(const uint8_t iv[QUIC_AEAD_IV_SIZE], uint64_t packet_number, uint8_t nonce[QUIC_AEAD_IV_SIZE]) {
    memcpy(nonce, iv, QUIC_AEAD_IV_SIZE);
    for (size_t i = 0; i < 8; i++) {
        nonce[QUIC_AEAD_IV_SIZE - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
    }
}

static int quic_compute_hp_mask(const uint8_t hp_key[QUIC_HP_KEY_SIZE], const uint8_t sample[QUIC_HP_SAMPLE_LEN], uint8_t mask[QUIC_HP_MASK_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t block[QUIC_HP_SAMPLE_LEN];
    int out_len = 0;
    int ok = -1;

    if (!ctx) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp_key, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto cleanup;
    if (EVP_EncryptUpdate(ctx, block, &out_len, sample, QUIC_HP_SAMPLE_LEN) != 1) goto cleanup;
    if (out_len < QUIC_HP_MASK_LEN) goto cleanup;

    memcpy(mask, block, QUIC_HP_MASK_LEN);
    ok = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int quic_aead_encrypt(
    const quic_crypto_level_ctx_t *ctx,
    uint64_t packet_number,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_len,
    size_t *written
) {
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    uint8_t nonce[QUIC_AEAD_IV_SIZE];
    int len = 0;
    int total = 0;
    int ok = -1;

    if (!cipher || ciphertext_len < plaintext_len + QUIC_AEAD_TAG_LEN) {
        EVP_CIPHER_CTX_free(cipher);
        return -1;
    }

    quic_build_nonce(ctx->iv, packet_number, nonce);

    if (EVP_EncryptInit_ex(cipher, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN, QUIC_AEAD_IV_SIZE, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(cipher, NULL, NULL, ctx->key, nonce) != 1) goto cleanup;
    if (EVP_EncryptUpdate(cipher, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    if (EVP_EncryptUpdate(cipher, ciphertext, &len, plaintext, (int)plaintext_len) != 1) goto cleanup;
    total += len;
    if (EVP_EncryptFinal_ex(cipher, ciphertext + total, &len) != 1) goto cleanup;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, QUIC_AEAD_TAG_LEN, ciphertext + total) != 1) goto cleanup;
    total += QUIC_AEAD_TAG_LEN;
    *written = (size_t)total;
    ok = 0;

cleanup:
    EVP_CIPHER_CTX_free(cipher);
    return ok;
}

static int quic_aead_decrypt(
    const quic_crypto_level_ctx_t *ctx,
    uint64_t packet_number,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_len,
    size_t *written
) {
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    uint8_t nonce[QUIC_AEAD_IV_SIZE];
    const uint8_t *tag;
    size_t body_len;
    int len = 0;
    int total = 0;
    int ok = -1;

    if (!cipher || ciphertext_len < QUIC_AEAD_TAG_LEN) {
        EVP_CIPHER_CTX_free(cipher);
        return -1;
    }

    body_len = ciphertext_len - QUIC_AEAD_TAG_LEN;
    tag = ciphertext + body_len;
    if (plaintext_len < body_len) {
        EVP_CIPHER_CTX_free(cipher);
        return -1;
    }

    quic_build_nonce(ctx->iv, packet_number, nonce);

    if (EVP_DecryptInit_ex(cipher, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN, QUIC_AEAD_IV_SIZE, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(cipher, NULL, NULL, ctx->key, nonce) != 1) goto cleanup;
    if (EVP_DecryptUpdate(cipher, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    if (EVP_DecryptUpdate(cipher, plaintext, &len, ciphertext, (int)body_len) != 1) goto cleanup;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, QUIC_AEAD_TAG_LEN, (void *)tag) != 1) goto cleanup;
    if (EVP_DecryptFinal_ex(cipher, plaintext + total, &len) != 1) goto cleanup;
    total += len;
    *written = (size_t)total;
    ok = 0;

cleanup:
    EVP_CIPHER_CTX_free(cipher);
    return ok;
}

size_t quic_packet_number_encode_size(uint64_t full_pn, uint64_t largest_acked) {
    uint64_t num_unacked = (largest_acked == UINT64_MAX) ? (full_pn + 1) : (full_pn - largest_acked);
    if (num_unacked < (1ULL << 7)) {
        return 1;
    }
    if (num_unacked < (1ULL << 15)) {
        return 2;
    }
    if (num_unacked < (1ULL << 23)) {
        return 3;
    }
    return 4;
}

int quic_encode_packet_number(uint64_t full_pn, size_t pn_len, uint8_t *out, size_t out_len) {
    if (!out || out_len < pn_len || pn_len == 0 || pn_len > 4) {
        return -1;
    }

    for (size_t i = 0; i < pn_len; i++) {
        out[pn_len - 1 - i] = (uint8_t)(full_pn >> (8 * i));
    }
    return 0;
}

uint64_t quic_decode_packet_number(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_nbits) {
    uint64_t expected_pn = largest_pn + 1;
    uint64_t pn_win = 1ULL << pn_nbits;
    uint64_t pn_hwin = pn_win / 2;
    uint64_t pn_mask = pn_win - 1;
    uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if (candidate_pn + pn_hwin <= expected_pn && candidate_pn < ((1ULL << 62) - pn_win)) {
        return candidate_pn + pn_win;
    }
    if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

static int quic_apply_header_protection(const quic_crypto_level_ctx_t *ctx, uint8_t *packet, size_t packet_len, size_t pn_offset) {
    uint8_t mask[QUIC_HP_MASK_LEN];
    size_t sample_offset = pn_offset + 4;
    size_t pn_len;

    if (!packet || sample_offset + QUIC_HP_SAMPLE_LEN > packet_len) {
        return -1;
    }
    if (quic_compute_hp_mask(ctx->hp, packet + sample_offset, mask) != 0) {
        return -1;
    }

    pn_len = (packet[0] & 0x03) + 1;
    packet[0] ^= (packet[0] & 0x80) ? (mask[0] & 0x0f) : (mask[0] & 0x1f);
    for (size_t i = 0; i < pn_len; i++) {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    return 0;
}

static int quic_remove_header_protection(const quic_crypto_level_ctx_t *ctx, uint8_t *packet, size_t packet_len, size_t pn_offset, size_t *pn_len) {
    uint8_t mask[QUIC_HP_MASK_LEN];
    size_t sample_offset = pn_offset + 4;

    if (!packet || !pn_len || sample_offset + QUIC_HP_SAMPLE_LEN > packet_len) {
        return -1;
    }
    if (quic_compute_hp_mask(ctx->hp, packet + sample_offset, mask) != 0) {
        return -1;
    }

    packet[0] ^= (packet[0] & 0x80) ? (mask[0] & 0x0f) : (mask[0] & 0x1f);
    *pn_len = (packet[0] & 0x03) + 1;
    if (pn_offset + *pn_len > packet_len) {
        return -1;
    }
    for (size_t i = 0; i < *pn_len; i++) {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    return 0;
}

int quic_packet_protect(
    const quic_crypto_level_ctx_t *ctx,
    uint64_t packet_number,
    const uint8_t *header,
    size_t header_len,
    size_t pn_offset,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_len,
    size_t *out_packet_len
) {
    size_t ciphertext_written = 0;

    if (!ctx || !header || !plaintext || !out_packet || !out_packet_len || pn_offset >= header_len) {
        return -1;
    }
    if (out_len < header_len + plaintext_len + QUIC_AEAD_TAG_LEN) {
        return -1;
    }

    memcpy(out_packet, header, header_len);
    if (quic_aead_encrypt(ctx, packet_number, out_packet, header_len,
                          plaintext, plaintext_len,
                          out_packet + header_len, out_len - header_len,
                          &ciphertext_written) != 0) {
        return -1;
    }

    *out_packet_len = header_len + ciphertext_written;
    if (quic_apply_header_protection(ctx, out_packet, *out_packet_len, pn_offset) != 0) {
        return -1;
    }
    return 0;
}

int quic_packet_unprotect(
    const quic_crypto_level_ctx_t *ctx,
    uint64_t largest_pn,
    uint8_t *packet,
    size_t packet_len,
    size_t pn_offset,
    uint64_t *packet_number,
    size_t *header_len,
    uint8_t *out_plaintext,
    size_t out_len,
    size_t *out_plaintext_len
) {
    size_t pn_len;
    size_t local_header_len;
    uint64_t truncated_pn = 0;

    if (!ctx || !packet || !packet_number || !header_len || !out_plaintext || !out_plaintext_len) {
        return -1;
    }
    if (quic_remove_header_protection(ctx, packet, packet_len, pn_offset, &pn_len) != 0) {
        return -1;
    }

    for (size_t i = 0; i < pn_len; i++) {
        truncated_pn = (truncated_pn << 8) | packet[pn_offset + i];
    }

    *packet_number = quic_decode_packet_number(largest_pn, truncated_pn, pn_len * 8);
    local_header_len = pn_offset + pn_len;
    *header_len = local_header_len;

    if (local_header_len > packet_len) {
        return -1;
    }
    if (quic_aead_decrypt(ctx, *packet_number, packet, local_header_len,
                          packet + local_header_len, packet_len - local_header_len,
                          out_plaintext, out_len, out_plaintext_len) != 0) {
        return -1;
    }
    return 0;
}
