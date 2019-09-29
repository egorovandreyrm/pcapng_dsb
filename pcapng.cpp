#include "pcapng.h"

#include <string.h>
#include <time.h>

#define BLOCK_SECTION_HEADER         0x0A0D0D0A
#define BLOCK_INTERFACE_DESCRIPTION  0x00000001
#define BLOCK_ENHANCED_PACKET        0x00000006
#define BLOCK_DECRYPTION_SECRETS     0x0000000a

#define SECTION_HEADER_MAGIC 0x1A2B3C4D

#define VERSION_MAJOR 1
#define VERSION_MINOR 0

#define SECTION_HEADER_MAGIC   0x1A2B3C4D
#define UNKNOWN_SECTION_LENGTH 0xFFFFFFFFFFFFFFFF
#define LINKTYPE_RAW           101;

#define SECRETS_TYPE_TLS_KEY_LOG 0x544c534b

typedef struct pcapng_block_header_s {
    uint32_t block_type;
    uint32_t block_total_length;
    /* x bytes block_body */
    /* uint32_t block_total_length */
} pcapng_block_header_t;

typedef struct pcapng_section_header_block_s {
    /* pcapng_block_header_t */
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint64_t section_length; /* might be -1 for unknown */
    /* ... Options ... */
} pcapng_section_header_block_t;

typedef struct pcapng_interface_description_block_s {
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
    /* ... Options ... */
} pcapng_interface_description_block_t;

typedef struct pcapng_enhanced_packet_block_s {
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
    /* ... Options ... */
} pcapng_enhanced_packet_block_t;

typedef struct pcapng_decryption_secrets_block_s {
    uint32_t secrets_type;
    uint32_t secrets_length;
    /* ... Secrets Data ... */
    /* ... Padding ... */
    /* ... Options ... */
} pcapng_decryption_secrets_block_t;

namespace PcapNg {

    size_t write_section_header_block(uint8_t *out_buffer, size_t out_buffer_len) {
        size_t block_total_length = 0;
        pcapng_block_header_t *p_block = NULL;
        pcapng_section_header_block_t *p_section_header_block = NULL;
        uint32_t *p_ending_block_total_length = NULL;

        block_total_length =
                sizeof(pcapng_block_header_t) +
                sizeof(pcapng_section_header_block_t) +
                sizeof(uint32_t);

        if (NULL == out_buffer) {
            return block_total_length;
        }

        if (block_total_length > out_buffer_len) {
            return 0;
        }

        p_block = (pcapng_block_header_t *) out_buffer;
        p_block->block_type = BLOCK_SECTION_HEADER;
        p_block->block_total_length = block_total_length;

        p_section_header_block = (pcapng_section_header_block_t *) (
                out_buffer + sizeof(pcapng_block_header_t));

        p_section_header_block->magic = SECTION_HEADER_MAGIC;
        p_section_header_block->version_major = VERSION_MAJOR;
        p_section_header_block->section_length = UNKNOWN_SECTION_LENGTH;

        p_ending_block_total_length = (uint32_t *) (out_buffer + block_total_length - sizeof(uint32_t));
        *p_ending_block_total_length = block_total_length;

        return block_total_length;
    }

    size_t write_network_interfaces_description_block(
            uint32_t snapshot_max_len, uint8_t *out_buffer, size_t out_buffer_len) {

        size_t block_total_length = 0;
        pcapng_block_header_t *p_block = NULL;
        pcapng_interface_description_block_t *p_interface_description_block = NULL;
        uint32_t *p_ending_block_total_length = NULL;

        block_total_length =
                sizeof(pcapng_block_header_t) +
                sizeof(pcapng_interface_description_block_t) +
                sizeof(uint32_t);

        if (NULL == out_buffer) {
            return block_total_length;
        }

        if (block_total_length > out_buffer_len) {
            return 0;
        }

        p_block = (pcapng_block_header_t *) out_buffer;
        p_block->block_type = BLOCK_INTERFACE_DESCRIPTION;
        p_block->block_total_length = block_total_length;

        p_interface_description_block = (pcapng_interface_description_block_t *) (
                out_buffer + sizeof(pcapng_block_header_t));

        p_interface_description_block->linktype = LINKTYPE_RAW;
        p_interface_description_block->snaplen = snapshot_max_len;

        p_ending_block_total_length = (uint32_t *) (out_buffer + block_total_length - sizeof(uint32_t));
        *p_ending_block_total_length = block_total_length;

        return block_total_length;
    }

    size_t write_enhanced_packet_block(
            const uint8_t *packet,
            const size_t packet_len,
            uint8_t *out_buffer,
            size_t out_buffer_len) {

        size_t block_total_length = 0;
        pcapng_block_header_t *p_block = NULL;
        pcapng_enhanced_packet_block_t *p_enhanced_packet_block = NULL;
        uint32_t *p_ending_block_total_length = NULL;
        size_t padding = 0;
        struct timeval tv;
        uint64_t ms_tv = 0;

        padding = 4 - packet_len % 4;

        block_total_length =
                sizeof(pcapng_block_header_t) +
                sizeof(pcapng_enhanced_packet_block_t) +
                packet_len + padding +
                sizeof(uint32_t);

        if (NULL == out_buffer) {
            return block_total_length;
        }

        if (block_total_length > out_buffer_len) {
            return 0;
        }

        p_block = (pcapng_block_header_t *) out_buffer;
        p_block->block_type = BLOCK_ENHANCED_PACKET;
        p_block->block_total_length = block_total_length;

        p_enhanced_packet_block = (pcapng_enhanced_packet_block_t *) (
                out_buffer + sizeof(pcapng_block_header_t));

        p_enhanced_packet_block->interface_id = 0;

        gettimeofday(&tv, NULL);
        ms_tv = (uint64_t) (tv.tv_sec) * 1000 + (uint64_t) (tv.tv_usec) / 1000;

        p_enhanced_packet_block->timestamp_high = (uint32_t) (ms_tv >> 32);
        p_enhanced_packet_block->timestamp_low = (uint32_t) ms_tv;

        p_enhanced_packet_block->captured_len = packet_len;
        p_enhanced_packet_block->packet_len = packet_len;

        memcpy(out_buffer + sizeof(pcapng_block_header_t) + sizeof(pcapng_enhanced_packet_block_t),
               packet,
               packet_len);

        p_ending_block_total_length = (uint32_t *) (out_buffer + block_total_length - sizeof(uint32_t));
        *p_ending_block_total_length = block_total_length;

        return block_total_length;
    }

    size_t write_decryption_secrets_block(
            const uint8_t *tls_key_log,
            const size_t tls_key_log_len,
            uint8_t *out_buffer,
            size_t out_buffer_len) {

        size_t block_total_length = 0;
        pcapng_block_header_t *p_block = NULL;
        pcapng_decryption_secrets_block_t *p_decryption_secrets_block = NULL;
        uint32_t *p_ending_block_total_length = NULL;
        size_t padding = 0;

        padding = 4 - tls_key_log_len % 4;

        block_total_length =
                sizeof(pcapng_block_header_t) +
                sizeof(pcapng_decryption_secrets_block_t) +
                tls_key_log_len + padding +
                sizeof(uint32_t);

        if (NULL == out_buffer) {
            return block_total_length;
        }

        if (block_total_length > out_buffer_len) {
            return 0;
        }

        p_block = (pcapng_block_header_t *) out_buffer;
        p_block->block_type = BLOCK_DECRYPTION_SECRETS;
        p_block->block_total_length = block_total_length;

        p_decryption_secrets_block = (pcapng_decryption_secrets_block_t *) (
                out_buffer + sizeof(pcapng_block_header_t));

        p_decryption_secrets_block->secrets_type = SECRETS_TYPE_TLS_KEY_LOG;
        p_decryption_secrets_block->secrets_length = tls_key_log_len;

        memcpy(out_buffer + sizeof(pcapng_block_header_t) + sizeof(pcapng_decryption_secrets_block_t),
               tls_key_log,
               tls_key_log_len);

        p_ending_block_total_length = (uint32_t *) (out_buffer + block_total_length - sizeof(uint32_t));
        *p_ending_block_total_length = block_total_length;

        return block_total_length;
    }
}
