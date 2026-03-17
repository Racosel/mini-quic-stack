#include "quic_transport_params.h"
#include "quic_varint.h"
#include <string.h>

static int quic_decode_param_varint(const uint8_t *data, size_t len, uint64_t *out) {
    size_t offset = 0;
    if (quic_decode_varint(data, len, &offset, out) != 0 || offset != len) {
        return -1;
    }
    return 0;
}

static int quic_encode_param_varint(uint64_t value, uint8_t *out, size_t out_len, size_t *written) {
    int rc = quic_encode_varint(value, out, out_len);
    if (rc < 0) {
        return -1;
    }
    *written = (size_t)rc;
    return 0;
}

static int quic_encode_param_header(uint64_t id, size_t value_len, uint8_t *out, size_t out_len, size_t *offset) {
    int rc = quic_encode_varint(id, out + *offset, out_len - *offset);
    if (rc < 0) return -1;
    *offset += (size_t)rc;

    rc = quic_encode_varint(value_len, out + *offset, out_len - *offset);
    if (rc < 0) return -1;
    *offset += (size_t)rc;
    return 0;
}

static int quic_encode_bytes_param(uint64_t id, const uint8_t *bytes, size_t len, uint8_t *out, size_t out_len, size_t *offset) {
    if (quic_encode_param_header(id, len, out, out_len, offset) != 0) {
        return -1;
    }
    if (*offset + len > out_len) {
        return -1;
    }
    memcpy(out + *offset, bytes, len);
    *offset += len;
    return 0;
}

static int quic_encode_varint_param(uint64_t id, uint64_t value, uint8_t *out, size_t out_len, size_t *offset) {
    uint8_t scratch[8];
    size_t value_len;
    if (quic_encode_param_varint(value, scratch, sizeof(scratch), &value_len) != 0) {
        return -1;
    }
    if (quic_encode_param_header(id, value_len, out, out_len, offset) != 0) {
        return -1;
    }
    if (*offset + value_len > out_len) {
        return -1;
    }
    memcpy(out + *offset, scratch, value_len);
    *offset += value_len;
    return 0;
}

void quic_transport_params_init(quic_transport_params_t *params) {
    memset(params, 0, sizeof(*params));
}

int quic_transport_params_decode(const uint8_t *data, size_t len, quic_transport_params_t *params) {
    size_t offset = 0;
    if (!data || !params) {
        return -1;
    }

    quic_transport_params_init(params);

    while (offset < len) {
        uint64_t param_id, param_len;
        size_t value_offset;
        if (quic_decode_varint(data, len, &offset, &param_id) != 0) return -1;
        if (quic_decode_varint(data, len, &offset, &param_len) != 0) return -1;
        if (offset + param_len > len) return -1;

        value_offset = offset;

        switch (param_id) {
            case QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
            case QUIC_TP_INITIAL_SOURCE_CONNECTION_ID:
            case QUIC_TP_RETRY_SOURCE_CONNECTION_ID: {
                quic_cid_param_t *target = NULL;
                if (param_len > MAX_CID_LEN) return -1;
                if (param_id == QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID) {
                    target = &params->original_destination_connection_id;
                } else if (param_id == QUIC_TP_INITIAL_SOURCE_CONNECTION_ID) {
                    target = &params->initial_source_connection_id;
                } else {
                    target = &params->retry_source_connection_id;
                }
                target->present = 1;
                target->cid.len = (uint8_t)param_len;
                memcpy(target->cid.data, data + value_offset, param_len);
                break;
            }

            case QUIC_TP_STATELESS_RESET_TOKEN:
                if (param_len != QUIC_STATELESS_RESET_TOKEN_LEN) return -1;
                params->stateless_reset_token.present = 1;
                memcpy(params->stateless_reset_token.token, data + value_offset, QUIC_STATELESS_RESET_TOKEN_LEN);
                break;

            case QUIC_TP_DISABLE_ACTIVE_MIGRATION:
                if (param_len != 0) return -1;
                params->disable_active_migration_present = 1;
                break;

            case QUIC_TP_PREFERRED_ADDRESS:
                if (param_len > QUIC_MAX_PREFERRED_ADDRESS_LEN) return -1;
                params->preferred_address.present = 1;
                params->preferred_address.len = (size_t)param_len;
                memcpy(params->preferred_address.bytes, data + value_offset, param_len);
                break;

            case QUIC_TP_VERSION_INFORMATION: {
                size_t count;
                if (param_len < 4 || ((param_len - 4) % 4) != 0) return -1;
                params->version_information.present = 1;
                params->version_information.chosen_version =
                    ((uint32_t)data[value_offset] << 24) |
                    ((uint32_t)data[value_offset + 1] << 16) |
                    ((uint32_t)data[value_offset + 2] << 8) |
                    (uint32_t)data[value_offset + 3];
                count = (param_len - 4) / 4;
                if (count > QUIC_MAX_VERSION_INFORMATION_ENTRIES) return -1;
                params->version_information.available_versions_len = count;
                for (size_t i = 0; i < count; i++) {
                    size_t base = value_offset + 4 + (i * 4);
                    params->version_information.available_versions[i] =
                        ((uint32_t)data[base] << 24) |
                        ((uint32_t)data[base + 1] << 16) |
                        ((uint32_t)data[base + 2] << 8) |
                        (uint32_t)data[base + 3];
                }
                break;
            }

            case QUIC_TP_MAX_IDLE_TIMEOUT:
                params->max_idle_timeout.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->max_idle_timeout.value) != 0) return -1;
                break;
            case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
                params->max_udp_payload_size.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->max_udp_payload_size.value) != 0) return -1;
                break;
            case QUIC_TP_INITIAL_MAX_DATA:
                params->initial_max_data.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->initial_max_data.value) != 0) return -1;
                break;
            case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                params->initial_max_stream_data_bidi_local.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->initial_max_stream_data_bidi_local.value) != 0) return -1;
                break;
            case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                params->initial_max_stream_data_bidi_remote.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->initial_max_stream_data_bidi_remote.value) != 0) return -1;
                break;
            case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
                params->initial_max_stream_data_uni.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->initial_max_stream_data_uni.value) != 0) return -1;
                break;
            case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
                params->initial_max_streams_bidi.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->initial_max_streams_bidi.value) != 0) return -1;
                break;
            case QUIC_TP_INITIAL_MAX_STREAMS_UNI:
                params->initial_max_streams_uni.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->initial_max_streams_uni.value) != 0) return -1;
                break;
            case QUIC_TP_ACK_DELAY_EXPONENT:
                params->ack_delay_exponent.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->ack_delay_exponent.value) != 0) return -1;
                break;
            case QUIC_TP_MAX_ACK_DELAY:
                params->max_ack_delay.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->max_ack_delay.value) != 0) return -1;
                break;
            case QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
                params->active_connection_id_limit.present = 1;
                if (quic_decode_param_varint(data + value_offset, param_len, &params->active_connection_id_limit.value) != 0) return -1;
                break;
            default:
                break;
        }

        offset += param_len;
    }

    return 0;
}

int quic_transport_params_encode(const quic_transport_params_t *params, uint8_t *out, size_t out_len) {
    size_t offset = 0;
    uint8_t scratch[4 + (QUIC_MAX_VERSION_INFORMATION_ENTRIES * 4)];

    if (!params || !out) {
        return -1;
    }

    if (params->original_destination_connection_id.present &&
        quic_encode_bytes_param(QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                                params->original_destination_connection_id.cid.data,
                                params->original_destination_connection_id.cid.len,
                                out, out_len, &offset) != 0) return -1;

    if (params->max_idle_timeout.present &&
        quic_encode_varint_param(QUIC_TP_MAX_IDLE_TIMEOUT, params->max_idle_timeout.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->stateless_reset_token.present &&
        quic_encode_bytes_param(QUIC_TP_STATELESS_RESET_TOKEN,
                                params->stateless_reset_token.token,
                                QUIC_STATELESS_RESET_TOKEN_LEN,
                                out, out_len, &offset) != 0) return -1;

    if (params->max_udp_payload_size.present &&
        quic_encode_varint_param(QUIC_TP_MAX_UDP_PAYLOAD_SIZE, params->max_udp_payload_size.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_max_data.present &&
        quic_encode_varint_param(QUIC_TP_INITIAL_MAX_DATA, params->initial_max_data.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_max_stream_data_bidi_local.present &&
        quic_encode_varint_param(QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                 params->initial_max_stream_data_bidi_local.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_max_stream_data_bidi_remote.present &&
        quic_encode_varint_param(QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                 params->initial_max_stream_data_bidi_remote.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_max_stream_data_uni.present &&
        quic_encode_varint_param(QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                                 params->initial_max_stream_data_uni.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_max_streams_bidi.present &&
        quic_encode_varint_param(QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                 params->initial_max_streams_bidi.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_max_streams_uni.present &&
        quic_encode_varint_param(QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                 params->initial_max_streams_uni.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->ack_delay_exponent.present &&
        quic_encode_varint_param(QUIC_TP_ACK_DELAY_EXPONENT, params->ack_delay_exponent.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->max_ack_delay.present &&
        quic_encode_varint_param(QUIC_TP_MAX_ACK_DELAY, params->max_ack_delay.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->disable_active_migration_present &&
        quic_encode_param_header(QUIC_TP_DISABLE_ACTIVE_MIGRATION, 0, out, out_len, &offset) != 0) return -1;

    if (params->preferred_address.present &&
        quic_encode_bytes_param(QUIC_TP_PREFERRED_ADDRESS, params->preferred_address.bytes,
                                params->preferred_address.len, out, out_len, &offset) != 0) return -1;

    if (params->active_connection_id_limit.present &&
        quic_encode_varint_param(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                                 params->active_connection_id_limit.value,
                                 out, out_len, &offset) != 0) return -1;

    if (params->initial_source_connection_id.present &&
        quic_encode_bytes_param(QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                                params->initial_source_connection_id.cid.data,
                                params->initial_source_connection_id.cid.len,
                                out, out_len, &offset) != 0) return -1;

    if (params->retry_source_connection_id.present &&
        quic_encode_bytes_param(QUIC_TP_RETRY_SOURCE_CONNECTION_ID,
                                params->retry_source_connection_id.cid.data,
                                params->retry_source_connection_id.cid.len,
                                out, out_len, &offset) != 0) return -1;

    if (params->version_information.present) {
        size_t value_len = 4 + (params->version_information.available_versions_len * 4);
        if (params->version_information.available_versions_len > QUIC_MAX_VERSION_INFORMATION_ENTRIES) {
            return -1;
        }
        scratch[0] = (uint8_t)(params->version_information.chosen_version >> 24);
        scratch[1] = (uint8_t)(params->version_information.chosen_version >> 16);
        scratch[2] = (uint8_t)(params->version_information.chosen_version >> 8);
        scratch[3] = (uint8_t)params->version_information.chosen_version;
        for (size_t i = 0; i < params->version_information.available_versions_len; i++) {
            size_t base = 4 + (i * 4);
            uint32_t version = params->version_information.available_versions[i];
            scratch[base] = (uint8_t)(version >> 24);
            scratch[base + 1] = (uint8_t)(version >> 16);
            scratch[base + 2] = (uint8_t)(version >> 8);
            scratch[base + 3] = (uint8_t)version;
        }
        if (quic_encode_bytes_param(QUIC_TP_VERSION_INFORMATION, scratch, value_len,
                                    out, out_len, &offset) != 0) return -1;
    }

    return (int)offset;
}
