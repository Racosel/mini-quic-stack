#include "quic_initial.h"
#include "quic_varint.h"
#include <string.h>

int quic_parse_initial_header(const uint8_t *packet, size_t packet_len, quic_initial_header_t *out) {
    size_t offset;
    uint8_t packet_type;

    if (!packet || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    if (quic_parse_header_meta(packet, packet_len, &out->meta) != 0) {
        return -1;
    }
    if (out->meta.header_form != 1) {
        return -1;
    }

    out->version_ops = quic_version_get_ops(out->meta.version);
    if (!out->version_ops) {
        return -1;
    }

    packet_type = out->version_ops->decode_packet_type(packet[0]);
    if (packet_type != 0) {
        return -1;
    }

    offset = 6 + out->meta.dest_cid.len + 1 + out->meta.src_cid.len;
    if (offset > packet_len) {
        return -1;
    }

    if (quic_decode_varint(packet, packet_len, &offset, &out->token_length) != 0) {
        return -1;
    }
    if (offset + out->token_length > packet_len) {
        return -1;
    }
    out->token = packet + offset;
    offset += out->token_length;

    if (quic_decode_varint(packet, packet_len, &offset, &out->length) != 0) {
        return -1;
    }
    if (offset + 4 > packet_len) {
        return -1;
    }

    out->pn_offset = offset;
    return 0;
}
