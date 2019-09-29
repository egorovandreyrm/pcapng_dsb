#pragma once

#include <stdint.h>
#include <stddef.h>

// if out_buffer is NULL, the function does nothing but return the size that is required to save the data.
size_t pcapng_write_section_header_block(uint8_t *out_buffer, size_t out_buffer_len);

// if out_buffer is NULL, the function does nothing but return the size that is required to save the data.
size_t pcapng_write_network_interfaces_description_block(
        uint32_t snapshot_max_len, uint8_t *out_buffer, size_t out_buffer_len);

// if out_buffer is NULL, the function does nothing but return the size that is required to save the data.
size_t pcapng_write_enhanced_packet_block(
        const uint8_t *packet,
        size_t packet_len,
        uint8_t *out_buffer,
        size_t out_buffer_len);

// if out_buffer is NULL, the function does nothing but return the size that is required to save the data.
size_t pcapng_write_decryption_secrets_block(
        const char *tls_key_log,
        size_t tls_key_log_len,
        uint8_t *out_buffer,
        size_t out_buffer_len);