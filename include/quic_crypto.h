#ifndef QUIC_CRYPTO_H
#define QUIC_CRYPTO_H

#include "quic_types.h"
#include "quic_version.h"

#define QUIC_MD_HASH_SIZE 32  // SHA-256 输出长度
#define QUIC_AEAD_KEY_SIZE 16 // AES-128-GCM 密钥长度
#define QUIC_AEAD_IV_SIZE 12  // AES-128-GCM IV 长度
#define QUIC_HP_KEY_SIZE 16   // 头部保护密钥长度

typedef struct {
    uint8_t secret[QUIC_MD_HASH_SIZE]; // Initial Secret
    uint8_t key[QUIC_AEAD_KEY_SIZE];   // AEAD 读/写密钥
    uint8_t iv[QUIC_AEAD_IV_SIZE];     // AEAD 初始化向量
    uint8_t hp[QUIC_HP_KEY_SIZE];      // Header Protection 密钥
} quic_crypto_level_ctx_t;

typedef struct {
    quic_crypto_level_ctx_t client_initial;
    quic_crypto_level_ctx_t server_initial;
} quic_crypto_context_t;

// 初始化 QUIC 的 Initial 密钥上下文
int quic_crypto_setup_initial_keys(
    const quic_cid_t *dcid, 
    const quic_version_ops_t *v_ops, 
    quic_crypto_context_t *ctx
);

#endif // QUIC_CRYPTO_H