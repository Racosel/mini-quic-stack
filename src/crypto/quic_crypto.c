#include "quic_crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

static int quic_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    size_t prk_len = QUIC_MD_HASH_SIZE;
    int ret = -1;

    if (EVP_PKEY_derive_init(pctx) > 0 &&
        EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) > 0 &&
        EVP_PKEY_derive(pctx, prk, &prk_len) > 0) {
        ret = 0;
    }

    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int quic_hkdf_expand(const uint8_t *prk, const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    size_t len = out_len;
    int ret = -1;

    if (EVP_PKEY_derive_init(pctx) > 0 &&
        EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, QUIC_MD_HASH_SIZE) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) > 0 &&
        EVP_PKEY_derive(pctx, out, &len) > 0) {
        ret = 0;
    }

    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int quic_hkdf_expand_label(const uint8_t *secret, const char *label, uint16_t out_len, uint8_t *out) {
    const char *prefix = "tls13 ";
    size_t prefix_len = 6;
    size_t label_len = strlen(label);
    
    uint8_t hkdf_info[128];
    size_t info_offset = 0;

    hkdf_info[info_offset++] = (out_len >> 8) & 0xFF;
    hkdf_info[info_offset++] = out_len & 0xFF;
    hkdf_info[info_offset++] = prefix_len + label_len;

    memcpy(&hkdf_info[info_offset], prefix, prefix_len);
    info_offset += prefix_len;
    memcpy(&hkdf_info[info_offset], label, label_len);
    info_offset += label_len;

    hkdf_info[info_offset++] = 0x00; // Context Length = 0

    return quic_hkdf_expand(secret, hkdf_info, info_offset, out, out_len);
}

int quic_crypto_setup_initial_keys(const quic_cid_t *dcid, const quic_version_ops_t *v_ops, quic_crypto_context_t *ctx) {
    if (!dcid || !v_ops || !ctx) return -1;

    uint8_t initial_secret[QUIC_MD_HASH_SIZE];

    if (quic_hkdf_extract(v_ops->initial_salt, v_ops->salt_len, dcid->data, dcid->len, initial_secret) != 0) return -1;

    if (quic_hkdf_expand_label(initial_secret, "client in", QUIC_MD_HASH_SIZE, ctx->client_initial.secret) != 0) return -1;
    if (quic_hkdf_expand_label(initial_secret, "server in", QUIC_MD_HASH_SIZE, ctx->server_initial.secret) != 0) return -1;

    if (quic_hkdf_expand_label(ctx->client_initial.secret, v_ops->hkdf_label_key, QUIC_AEAD_KEY_SIZE, ctx->client_initial.key) != 0) return -1;
    if (quic_hkdf_expand_label(ctx->client_initial.secret, v_ops->hkdf_label_iv, QUIC_AEAD_IV_SIZE, ctx->client_initial.iv) != 0) return -1;
    if (quic_hkdf_expand_label(ctx->client_initial.secret, v_ops->hkdf_label_hp, QUIC_HP_KEY_SIZE, ctx->client_initial.hp) != 0) return -1;

    if (quic_hkdf_expand_label(ctx->server_initial.secret, v_ops->hkdf_label_key, QUIC_AEAD_KEY_SIZE, ctx->server_initial.key) != 0) return -1;
    if (quic_hkdf_expand_label(ctx->server_initial.secret, v_ops->hkdf_label_iv, QUIC_AEAD_IV_SIZE, ctx->server_initial.iv) != 0) return -1;
    if (quic_hkdf_expand_label(ctx->server_initial.secret, v_ops->hkdf_label_hp, QUIC_HP_KEY_SIZE, ctx->server_initial.hp) != 0) return -1;

    return 0;
}