#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "quic_retry.h"
#include "quic_transport_params.h"
#include "quic_types.h"

void test_transport_params_roundtrip() {
    quic_transport_params_t params;
    quic_transport_params_t decoded;
    uint8_t encoded[256];
    int len;

    quic_transport_params_init(&params);
    params.original_destination_connection_id.present = 1;
    params.original_destination_connection_id.cid.len = 4;
    params.original_destination_connection_id.cid.data[0] = 0x01;
    params.original_destination_connection_id.cid.data[1] = 0x02;
    params.original_destination_connection_id.cid.data[2] = 0x03;
    params.original_destination_connection_id.cid.data[3] = 0x04;
    params.max_idle_timeout.present = 1;
    params.max_idle_timeout.value = 30;
    params.max_udp_payload_size.present = 1;
    params.max_udp_payload_size.value = 1200;
    params.initial_max_data.present = 1;
    params.initial_max_data.value = 1024;
    params.initial_max_stream_data_bidi_local.present = 1;
    params.initial_max_stream_data_bidi_local.value = 2048;
    params.initial_max_stream_data_bidi_remote.present = 1;
    params.initial_max_stream_data_bidi_remote.value = 4096;
    params.initial_max_stream_data_uni.present = 1;
    params.initial_max_stream_data_uni.value = 512;
    params.initial_max_streams_bidi.present = 1;
    params.initial_max_streams_bidi.value = 8;
    params.initial_max_streams_uni.present = 1;
    params.initial_max_streams_uni.value = 4;
    params.ack_delay_exponent.present = 1;
    params.ack_delay_exponent.value = 3;
    params.max_ack_delay.present = 1;
    params.max_ack_delay.value = 25;
    params.active_connection_id_limit.present = 1;
    params.active_connection_id_limit.value = 4;
    params.disable_active_migration_present = 1;
    params.stateless_reset_token.present = 1;
    for (size_t i = 0; i < QUIC_STATELESS_RESET_TOKEN_LEN; i++) {
        params.stateless_reset_token.token[i] = (uint8_t)i;
    }
    params.preferred_address.present = 1;
    params.preferred_address.len = 8;
    for (size_t i = 0; i < params.preferred_address.len; i++) {
        params.preferred_address.bytes[i] = (uint8_t)(0xa0 + i);
    }
    params.initial_source_connection_id.present = 1;
    params.initial_source_connection_id.cid.len = 4;
    params.initial_source_connection_id.cid.data[0] = 0xaa;
    params.initial_source_connection_id.cid.data[1] = 0xbb;
    params.initial_source_connection_id.cid.data[2] = 0xcc;
    params.initial_source_connection_id.cid.data[3] = 0xdd;
    params.retry_source_connection_id.present = 1;
    params.retry_source_connection_id.cid.len = 4;
    params.retry_source_connection_id.cid.data[0] = 0x10;
    params.retry_source_connection_id.cid.data[1] = 0x20;
    params.retry_source_connection_id.cid.data[2] = 0x30;
    params.retry_source_connection_id.cid.data[3] = 0x40;
    params.version_information.present = 1;
    params.version_information.chosen_version = QUIC_V2_VERSION;
    params.version_information.available_versions[0] = QUIC_V2_VERSION;
    params.version_information.available_versions[1] = QUIC_V1_VERSION;
    params.version_information.available_versions_len = 2;

    len = quic_transport_params_encode(&params, encoded, sizeof(encoded));
    assert(len > 0);
    assert(quic_transport_params_decode(encoded, (size_t)len, &decoded) == 0);
    assert(decoded.original_destination_connection_id.present);
    assert(decoded.original_destination_connection_id.cid.len == 4);
    assert(memcmp(decoded.original_destination_connection_id.cid.data,
                  params.original_destination_connection_id.cid.data, 4) == 0);
    assert(decoded.max_idle_timeout.present && decoded.max_idle_timeout.value == 30);
    assert(decoded.max_udp_payload_size.present && decoded.max_udp_payload_size.value == 1200);
    assert(decoded.initial_max_data.present && decoded.initial_max_data.value == 1024);
    assert(decoded.initial_max_stream_data_bidi_local.present &&
           decoded.initial_max_stream_data_bidi_local.value == 2048);
    assert(decoded.initial_max_stream_data_bidi_remote.present &&
           decoded.initial_max_stream_data_bidi_remote.value == 4096);
    assert(decoded.initial_max_stream_data_uni.present &&
           decoded.initial_max_stream_data_uni.value == 512);
    assert(decoded.initial_max_streams_bidi.present &&
           decoded.initial_max_streams_bidi.value == 8);
    assert(decoded.initial_max_streams_uni.present &&
           decoded.initial_max_streams_uni.value == 4);
    assert(decoded.ack_delay_exponent.present &&
           decoded.ack_delay_exponent.value == 3);
    assert(decoded.max_ack_delay.present &&
           decoded.max_ack_delay.value == 25);
    assert(decoded.active_connection_id_limit.present && decoded.active_connection_id_limit.value == 4);
    assert(decoded.disable_active_migration_present == 1);
    assert(decoded.stateless_reset_token.present);
    assert(memcmp(decoded.stateless_reset_token.token,
                  params.stateless_reset_token.token,
                  QUIC_STATELESS_RESET_TOKEN_LEN) == 0);
    assert(decoded.preferred_address.present);
    assert(decoded.preferred_address.len == params.preferred_address.len);
    assert(memcmp(decoded.preferred_address.bytes,
                  params.preferred_address.bytes,
                  params.preferred_address.len) == 0);
    assert(decoded.initial_source_connection_id.present);
    assert(decoded.initial_source_connection_id.cid.len == 4);
    assert(memcmp(decoded.initial_source_connection_id.cid.data,
                  params.initial_source_connection_id.cid.data, 4) == 0);
    assert(decoded.retry_source_connection_id.present);
    assert(decoded.retry_source_connection_id.cid.len == 4);
    assert(memcmp(decoded.retry_source_connection_id.cid.data,
                  params.retry_source_connection_id.cid.data, 4) == 0);
    assert(decoded.version_information.present);
    assert(decoded.version_information.chosen_version == QUIC_V2_VERSION);
    assert(decoded.version_information.available_versions_len == 2);
    assert(decoded.version_information.available_versions[0] == QUIC_V2_VERSION);
    assert(decoded.version_information.available_versions[1] == QUIC_V1_VERSION);

    printf("[PASS] Transport parameter encode/decode roundtrip\n");
}

void test_retry_integrity_v1_v2() {
    quic_cid_t odcid = { .len = 8, .data = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08} };
    uint8_t retry_without_tag[] = {
        0xf0, 0x6b, 0x33, 0x43, 0xcf, 0x08,
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        't', 'o', 'k', 'e', 'n'
    };
    uint8_t retry_packet_v2[sizeof(retry_without_tag) + QUIC_RETRY_INTEGRITY_TAG_LEN];
    uint8_t retry_packet_v1[sizeof(retry_without_tag) + QUIC_RETRY_INTEGRITY_TAG_LEN];
    uint8_t tag_v2[QUIC_RETRY_INTEGRITY_TAG_LEN];
    uint8_t tag_v1[QUIC_RETRY_INTEGRITY_TAG_LEN];

    assert(quic_retry_compute_integrity_tag(QUIC_V2_VERSION, &odcid,
                                            retry_without_tag, sizeof(retry_without_tag), tag_v2) == 0);
    assert(quic_retry_compute_integrity_tag(QUIC_V1_VERSION, &odcid,
                                            retry_without_tag, sizeof(retry_without_tag), tag_v1) == 0);
    assert(memcmp(tag_v1, tag_v2, QUIC_RETRY_INTEGRITY_TAG_LEN) != 0);

    memcpy(retry_packet_v2, retry_without_tag, sizeof(retry_without_tag));
    memcpy(retry_packet_v2 + sizeof(retry_without_tag), tag_v2, QUIC_RETRY_INTEGRITY_TAG_LEN);
    memcpy(retry_packet_v1, retry_without_tag, sizeof(retry_without_tag));
    memcpy(retry_packet_v1 + sizeof(retry_without_tag), tag_v1, QUIC_RETRY_INTEGRITY_TAG_LEN);

    assert(quic_retry_verify_integrity_tag(QUIC_V2_VERSION, &odcid,
                                           retry_packet_v2, sizeof(retry_packet_v2)) == 0);
    assert(quic_retry_verify_integrity_tag(QUIC_V1_VERSION, &odcid,
                                           retry_packet_v1, sizeof(retry_packet_v1)) == 0);

    retry_packet_v2[sizeof(retry_packet_v2) - 1] ^= 0xff;
    assert(quic_retry_verify_integrity_tag(QUIC_V2_VERSION, &odcid,
                                           retry_packet_v2, sizeof(retry_packet_v2)) != 0);

    printf("[PASS] Retry integrity tag generation and verification\n");
}

int main() {
    printf("--- Running Phase 7 Tests ---\n");
    test_transport_params_roundtrip();
    test_retry_integrity_v1_v2();
    printf("--- All Phase 7 Tests Passed! ---\n");
    return 0;
}
