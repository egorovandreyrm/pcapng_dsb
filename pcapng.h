#pragma once

#include <stdint.h>

namespace PcapNg {

    size_t write_section_header_block(uint8_t *out_buffer, size_t out_buffer_len);

    size_t write_network_interfaces_description_block(
            uint32_t snapshot_max_len, uint8_t *out_buffer, size_t out_buffer_len);

    size_t write_enhanced_packet_block(
            const uint8_t *packet,
            const size_t packet_len,
            uint8_t *out_buffer,
            size_t out_buffer_len);

    size_t write_decryption_secrets_block(
            const uint8_t *tls_key_log,
            const size_t tls_key_log_len,
            uint8_t *out_buffer,
            size_t out_buffer_len);
}