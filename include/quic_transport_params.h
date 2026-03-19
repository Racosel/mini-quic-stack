#ifndef QUIC_TRANSPORT_PARAMS_H
#define QUIC_TRANSPORT_PARAMS_H

#include "quic_types.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_STATELESS_RESET_TOKEN_LEN 16
#define QUIC_MAX_PREFERRED_ADDRESS_LEN 64
#define QUIC_MAX_VERSION_INFORMATION_ENTRIES 8

#define QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID 0x00
#define QUIC_TP_MAX_IDLE_TIMEOUT 0x01
#define QUIC_TP_STATELESS_RESET_TOKEN 0x02
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE 0x03
#define QUIC_TP_INITIAL_MAX_DATA 0x04
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x05
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI 0x07
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI 0x08
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI 0x09
#define QUIC_TP_ACK_DELAY_EXPONENT 0x0a
#define QUIC_TP_MAX_ACK_DELAY 0x0b
#define QUIC_TP_DISABLE_ACTIVE_MIGRATION 0x0c
#define QUIC_TP_PREFERRED_ADDRESS 0x0d
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT 0x0e
#define QUIC_TP_INITIAL_SOURCE_CONNECTION_ID 0x0f
#define QUIC_TP_RETRY_SOURCE_CONNECTION_ID 0x10
#define QUIC_TP_VERSION_INFORMATION 0x11

typedef struct {
    uint8_t present;
    uint64_t value;
} quic_transport_varint_param_t;

typedef struct {
    uint8_t present;
    uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN];
} quic_stateless_reset_token_t;

typedef struct {
    uint8_t present;
    uint8_t bytes[QUIC_MAX_PREFERRED_ADDRESS_LEN];
    size_t len;
} quic_preferred_address_param_t;

typedef struct {
    uint8_t present;
    uint32_t chosen_version;
    uint32_t available_versions[QUIC_MAX_VERSION_INFORMATION_ENTRIES];
    size_t available_versions_len;
} quic_version_information_param_t;

typedef struct {
    uint8_t present;
    quic_cid_t cid;
} quic_cid_param_t;

typedef struct {
    quic_cid_param_t original_destination_connection_id;
    quic_transport_varint_param_t max_idle_timeout;
    quic_stateless_reset_token_t stateless_reset_token;
    quic_transport_varint_param_t max_udp_payload_size;
    quic_transport_varint_param_t initial_max_data;
    quic_transport_varint_param_t initial_max_stream_data_bidi_local;
    quic_transport_varint_param_t initial_max_stream_data_bidi_remote;
    quic_transport_varint_param_t initial_max_stream_data_uni;
    quic_transport_varint_param_t initial_max_streams_bidi;
    quic_transport_varint_param_t initial_max_streams_uni;
    quic_transport_varint_param_t ack_delay_exponent;
    quic_transport_varint_param_t max_ack_delay;
    uint8_t disable_active_migration_present;
    quic_preferred_address_param_t preferred_address;
    quic_transport_varint_param_t active_connection_id_limit;
    quic_cid_param_t initial_source_connection_id;
    quic_cid_param_t retry_source_connection_id;
    quic_version_information_param_t version_information;
} quic_transport_params_t;

// 功能：把 transport parameters 结构初始化为“未设置任何字段”的空状态。
// 返回值：无。
void quic_transport_params_init(quic_transport_params_t *params);
// 功能：从字节串解码 QUIC transport parameters。
// 返回值：0 表示成功；< 0 表示编码不合法、字段冲突或长度不足。
int quic_transport_params_decode(const uint8_t *data, size_t len, quic_transport_params_t *params);
// 功能：把 QUIC transport parameters 编码到输出缓冲区。
// 返回值：>= 0 表示编码后的总长度；< 0 表示输出缓冲区不足或输入参数无效。
int quic_transport_params_encode(const quic_transport_params_t *params, uint8_t *out, size_t out_len);

#endif // QUIC_TRANSPORT_PARAMS_H：头文件保护结束
