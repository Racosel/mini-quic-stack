#include "quic_ack.h"
#include "quic_frame.h"
#include "quic_varint.h"
#include <string.h>

static int quic_pn_in_ack_ranges(uint64_t pn, const quic_ack_frame_t *ack) {
    for (size_t i = 0; i < ack->ack_range_count; i++) {
        if (pn >= ack->ranges[i].smallest && pn <= ack->ranges[i].largest) {
            return 1;
        }
    }
    return 0;
}

void quic_ack_ranges_init(quic_ack_range_t *ranges, size_t *range_count) {
    if (!ranges || !range_count) {
        return;
    }
    memset(ranges, 0, sizeof(quic_ack_range_t) * QUIC_MAX_ACK_RANGES);
    *range_count = 0;
}

int quic_ack_note_received(quic_ack_range_t *ranges, size_t *range_count, uint64_t packet_number) {
    size_t count;
    size_t insert_at;
    size_t i;

    if (!ranges || !range_count) {
        return -1;
    }

    count = *range_count;
    for (i = 0; i < count; i++) {
        if (packet_number >= ranges[i].smallest && packet_number <= ranges[i].largest) {
            return 0;
        }
    }

    insert_at = count;
    for (i = 0; i < count; i++) {
        if (packet_number > ranges[i].largest) {
            insert_at = i;
            break;
        }
    }

    if (count == QUIC_MAX_ACK_RANGES) {
        if (insert_at == count) {
            return 0;
        }
        count--;
    }

    for (i = count; i > insert_at; i--) {
        ranges[i] = ranges[i - 1];
    }
    ranges[insert_at].largest = packet_number;
    ranges[insert_at].smallest = packet_number;
    count++;

    i = 0;
    while (i + 1 < count) {
        if (ranges[i].smallest <= ranges[i + 1].largest + 1) {
            if (ranges[i + 1].smallest < ranges[i].smallest) {
                ranges[i].smallest = ranges[i + 1].smallest;
            }
            memmove(&ranges[i + 1],
                    &ranges[i + 2],
                    sizeof(quic_ack_range_t) * (count - (i + 2)));
            count--;
            continue;
        }
        i++;
    }

    *range_count = count;
    return 0;
}

int quic_ack_frame_from_ranges(const quic_ack_range_t *ranges, size_t range_count, quic_ack_frame_t *ack) {
    if (!ranges || !ack || range_count == 0 || range_count > QUIC_MAX_ACK_RANGES) {
        return -1;
    }

    memset(ack, 0, sizeof(*ack));
    ack->largest_acked = ranges[0].largest;
    ack->ack_range_count = range_count;
    memcpy(ack->ranges, ranges, sizeof(quic_ack_range_t) * range_count);
    return 0;
}

int quic_ack_parse_frame(const uint8_t *frame, size_t frame_len, quic_ack_frame_t *ack, size_t *consumed) {
    size_t offset = 0;
    uint64_t frame_type, ack_range_count, first_ack_range;
    uint64_t range_largest, range_smallest;

    if (!frame || !ack || !consumed) {
        return -1;
    }
    memset(ack, 0, sizeof(*ack));

    if (quic_decode_varint(frame, frame_len, &offset, &frame_type) != 0) return -1;
    if (frame_type != 0x02 && frame_type != 0x03) return -1;
    ack->has_ecn = (frame_type == 0x03);

    if (quic_decode_varint(frame, frame_len, &offset, &ack->largest_acked) != 0) return -1;
    if (quic_decode_varint(frame, frame_len, &offset, &ack->ack_delay) != 0) return -1;
    if (quic_decode_varint(frame, frame_len, &offset, &ack_range_count) != 0) return -1;
    if (quic_decode_varint(frame, frame_len, &offset, &first_ack_range) != 0) return -1;

    if (ack_range_count + 1 > QUIC_MAX_ACK_RANGES) {
        return -1;
    }
    if (ack->largest_acked < first_ack_range) {
        return -1;
    }

    range_largest = ack->largest_acked;
    range_smallest = range_largest - first_ack_range;
    ack->ranges[0].largest = range_largest;
    ack->ranges[0].smallest = range_smallest;
    ack->ack_range_count = 1;

    for (uint64_t i = 0; i < ack_range_count; i++) {
        uint64_t gap, ack_range_length;
        if (quic_decode_varint(frame, frame_len, &offset, &gap) != 0) return -1;
        if (quic_decode_varint(frame, frame_len, &offset, &ack_range_length) != 0) return -1;
        if (range_smallest < gap + 2) return -1;

        range_largest = range_smallest - gap - 2;
        if (range_largest < ack_range_length) return -1;
        range_smallest = range_largest - ack_range_length;

        ack->ranges[ack->ack_range_count].largest = range_largest;
        ack->ranges[ack->ack_range_count].smallest = range_smallest;
        ack->ack_range_count++;
    }

    if (ack->has_ecn) {
        if (quic_decode_varint(frame, frame_len, &offset, &ack->ect0_count) != 0) return -1;
        if (quic_decode_varint(frame, frame_len, &offset, &ack->ect1_count) != 0) return -1;
        if (quic_decode_varint(frame, frame_len, &offset, &ack->ecn_ce_count) != 0) return -1;
    }

    *consumed = offset;
    return 0;
}

int quic_ack_encode_frame(const quic_ack_frame_t *ack, uint8_t *out, size_t out_len, size_t *written) {
    size_t offset = 0;
    int rc;

    if (!ack || !out || !written || ack->ack_range_count == 0) {
        return -1;
    }
    if (ack->has_ecn) {
        return -1;
    }
    if (ack->ranges[0].largest != ack->largest_acked ||
        ack->ranges[0].smallest > ack->ranges[0].largest) {
        return -1;
    }

    rc = quic_encode_varint(ack->has_ecn ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK, out + offset, out_len - offset);
    if (rc < 0) return -1;
    offset += (size_t)rc;

    rc = quic_encode_varint(ack->largest_acked, out + offset, out_len - offset);
    if (rc < 0) return -1;
    offset += (size_t)rc;

    rc = quic_encode_varint(ack->ack_delay, out + offset, out_len - offset);
    if (rc < 0) return -1;
    offset += (size_t)rc;

    rc = quic_encode_varint(ack->ack_range_count - 1, out + offset, out_len - offset);
    if (rc < 0) return -1;
    offset += (size_t)rc;

    rc = quic_encode_varint(ack->ranges[0].largest - ack->ranges[0].smallest, out + offset, out_len - offset);
    if (rc < 0) return -1;
    offset += (size_t)rc;

    for (size_t i = 1; i < ack->ack_range_count; i++) {
        uint64_t gap;
        uint64_t range_len;

        if (ack->ranges[i].smallest > ack->ranges[i].largest ||
            ack->ranges[i - 1].smallest < ack->ranges[i].largest + 2) {
            return -1;
        }

        gap = ack->ranges[i - 1].smallest - ack->ranges[i].largest - 2;
        range_len = ack->ranges[i].largest - ack->ranges[i].smallest;

        rc = quic_encode_varint(gap, out + offset, out_len - offset);
        if (rc < 0) return -1;
        offset += (size_t)rc;

        rc = quic_encode_varint(range_len, out + offset, out_len - offset);
        if (rc < 0) return -1;
        offset += (size_t)rc;
    }

    *written = offset;
    return 0;
}

int quic_on_ack_frame(quic_in_flight_queue_t *q, const quic_ack_frame_t *ack, size_t *acked_packets) {
    quic_sent_packet_t *curr;
    quic_sent_packet_t *next;
    size_t count = 0;

    if (!q || !ack || !acked_packets) {
        return -1;
    }

    curr = q->head;
    while (curr) {
        next = curr->next;
        if (quic_pn_in_ack_ranges(curr->packet_number, ack)) {
            quic_on_packet_acked(q, curr->packet_number);
            count++;
        }
        curr = next;
    }

    *acked_packets = count;
    return 0;
}
