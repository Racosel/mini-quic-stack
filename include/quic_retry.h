#ifndef QUIC_RETRY_H
#define QUIC_RETRY_H

#include "quic_types.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_RETRY_INTEGRITY_TAG_LEN 16

int quic_retry_compute_integrity_tag(
    uint32_t version,
    const quic_cid_t *original_dcid,
    const uint8_t *retry_without_tag,
    size_t retry_without_tag_len,
    uint8_t out_tag[QUIC_RETRY_INTEGRITY_TAG_LEN]
);

int quic_retry_verify_integrity_tag(
    uint32_t version,
    const quic_cid_t *original_dcid,
    const uint8_t *retry_packet,
    size_t retry_packet_len
);

#endif // QUIC_RETRY_H：头文件保护结束
