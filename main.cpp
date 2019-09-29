#include "pcapng.h"

#include <stdio.h>

// SYN
uint8_t packet1[] = {
        0x45, 0x00, 0x00, 0x3c, 0x2b, 0x47, 0x40, 0x00, 0x40, 0x06, 0xd3, 0x12, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x01, 0x1a, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0xff, 0xff, 0xf4, 0x05, 0x00, 0x00, 0x02, 0x04, 0x26, 0xe8, 0x04, 0x02, 0x08, 0x0a,
        0x00, 0x18, 0x2a, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
};

// SYN ASK
uint8_t packet2[] = {
        0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x3e, 0x66, 0xb9, 0xc7, 0x6e, 0x99,
        0x0a, 0x01, 0x0a, 0x01, 0x01, 0xbb, 0xda, 0x6a, 0x5a, 0x4f, 0x19, 0x9c, 0xee, 0xae, 0x01, 0x1b,
        0x70, 0x12, 0x3f, 0x40, 0xe7, 0x1e, 0x00, 0x00, 0x02, 0x04, 0xe8, 0x26, 0x03, 0x03, 0x00, 0x00
};

// ASK
uint8_t packet3[] = {
        0x45, 0x00, 0x00, 0x28, 0x2b, 0x48, 0x40, 0x00, 0x40, 0x06, 0xd3, 0x25, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x01, 0x1b, 0x5a, 0x4f, 0x19, 0x9d,
        0x50, 0x10, 0x02, 0x6f, 0x31, 0x27, 0x00, 0x00
};

// client hello
uint8_t packet4[] = {
        0x45, 0x00, 0x00, 0xd9, 0x2b, 0x49, 0x40, 0x00, 0x40, 0x06, 0xd2, 0x73, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x01, 0x1b, 0x5a, 0x4f, 0x19, 0x9d,
        0x50, 0x18, 0x02, 0x6f, 0xbd, 0x69, 0x00, 0x00, 0x16, 0x03, 0x01, 0x00, 0xac, 0x01, 0x00, 0x00,
        0xa8, 0x03, 0x03, 0xa0, 0x82, 0x37, 0xc6, 0xcc, 0x3d, 0xb9, 0x0e, 0x6c, 0xfe, 0xcf, 0xb5, 0xcb,
        0x26, 0x9b, 0x8f, 0x84, 0xdb, 0x5f, 0x21, 0x78, 0x6d, 0x75, 0x0e, 0x68, 0xe0, 0x03, 0xff, 0x8e,
        0x18, 0xb7, 0xb4, 0x00, 0x00, 0x18, 0xc0, 0x2b, 0xc0, 0x2c, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30,
        0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00,
        0x00, 0x67, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13, 0x00, 0x00, 0x10,
        0x73, 0x71, 0x75, 0x61, 0x72, 0x65, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f,
        0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03,
        0x04, 0x01, 0x05, 0x03, 0x05, 0x01, 0x06, 0x03, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x05,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68,
        0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00,
        0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18
};

// ASK
uint8_t packet5[] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x3e, 0x6e, 0xb9, 0xc7, 0x6e, 0x99,
        0x0a, 0x01, 0x0a, 0x01, 0x01, 0xbb, 0xda, 0x6a, 0x5a, 0x4f, 0x19, 0x9d, 0xee, 0xae, 0x01, 0xcc,
        0x50, 0x10, 0x3f, 0x40, 0xf3, 0xa4, 0x00, 0x00
};

// server hello
uint8_t packet6[] = {
        0x45, 0x00, 0x04, 0x71, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x3a, 0x25, 0xb9, 0xc7, 0x6e, 0x99,
        0x0a, 0x01, 0x0a, 0x01, 0x01, 0xbb, 0xda, 0x6a, 0x5a, 0x4f, 0x19, 0x9d, 0xee, 0xae, 0x01, 0xcc,
        0x50, 0x10, 0x3f, 0x40, 0x62, 0xfe, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x35, 0x02, 0x00, 0x00,
        0x31, 0x03, 0x03, 0x5d, 0x90, 0x87, 0x92, 0xe8, 0x09, 0x67, 0x42, 0x5f, 0x3a, 0x22, 0xac, 0xd9,
        0x90, 0x3b, 0x75, 0xeb, 0x8d, 0xc6, 0xcd, 0xc7, 0x1f, 0xe9, 0xd5, 0xba, 0xc6, 0x06, 0xf0, 0x29,
        0x23, 0xe6, 0x65, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x09, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00,
        0x01, 0x00, 0x16, 0x03, 0x03, 0x04, 0x01, 0x0b, 0x00, 0x03, 0xfd, 0x00, 0x03, 0xfa, 0x00, 0x03,
        0xf7, 0x30, 0x82, 0x03, 0xf3, 0x30, 0x82, 0x02, 0xdb, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09,
        0x00, 0xfe, 0x19, 0x05, 0xbf, 0x57, 0x7e, 0xc5, 0x7a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x6d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0c, 0x04, 0x4d, 0x49, 0x54, 0x4d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
        0x04, 0x4d, 0x49, 0x54, 0x4d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x04,
        0x4d, 0x49, 0x54, 0x4d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x4d,
        0x49, 0x54, 0x4d, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x4d, 0x49,
        0x54, 0x4d, 0x31, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
        0x01, 0x16, 0x04, 0x4d, 0x49, 0x54, 0x4d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x39, 0x32,
        0x39, 0x31, 0x30, 0x32, 0x39, 0x33, 0x38, 0x5a, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x39, 0x32, 0x38,
        0x31, 0x30, 0x32, 0x39, 0x33, 0x38, 0x5a, 0x30, 0x81, 0x83, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d, 0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63,
        0x69, 0x73, 0x63, 0x6f, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x47,
        0x69, 0x74, 0x48, 0x75, 0x62, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x17, 0x30, 0x15, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x13, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
        0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x77,
        0x77, 0x77, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x01,
        0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdb, 0x15,
        0x4c, 0xc9, 0x65, 0xf8, 0x77, 0x7b, 0x3d, 0xeb, 0x5e, 0x3c, 0xbd, 0xb7, 0x93, 0x5f, 0xcf, 0x05,
        0xe9, 0xea, 0xc2, 0xa6, 0xe8, 0xfc, 0x23, 0xda, 0x2e, 0xa9, 0x44, 0x92, 0xc3, 0x1b, 0xab, 0x80,
        0x93, 0xb8, 0x63, 0xf2, 0x74, 0xde, 0xb8, 0xd8, 0x35, 0x0b, 0xd7, 0xda, 0xbb, 0x7d, 0xd5, 0xbe,
        0xae, 0x0b, 0xee, 0xad, 0xfe, 0x04, 0xc7, 0xa8, 0xb8, 0xf2, 0x45, 0x67, 0x54, 0xfa, 0x0f, 0x7e,
        0xa3, 0x7f, 0x68, 0xe2, 0x3f, 0x45, 0x4c, 0x25, 0x94, 0x5f, 0x14, 0x5a, 0xcf, 0xf2, 0x82, 0x54,
        0x9d, 0x7d, 0xc5, 0xdc, 0x90, 0x6f, 0x63, 0x99, 0xcc, 0xb8, 0xa4, 0xd7, 0xad, 0x9c, 0x83, 0xff,
        0xaf, 0x54, 0x63, 0x0d, 0x4d, 0xb8, 0x2d, 0x20, 0x1c, 0x3f, 0x11, 0xf9, 0xbe, 0x8c, 0x16, 0xe7,
        0x0d, 0x37, 0xf3, 0x61, 0xc2, 0xde, 0x51, 0xa7, 0x2c, 0xf2, 0x84, 0xd9, 0x32, 0x2d, 0x1f, 0x2d,
        0x92, 0x78, 0x1a, 0x92, 0x8d, 0xdd, 0xf4, 0x4a, 0x8b, 0x17, 0xd0, 0xc8, 0x43, 0xa7, 0x3a, 0xd3,
        0xc8, 0x6a, 0xfc, 0xdc, 0xcc, 0x0f, 0x21, 0x36, 0x44, 0x42, 0xc5, 0x89, 0x27, 0xad, 0x20, 0xde,
        0xaf, 0xab, 0x3e, 0xf9, 0x7d, 0xac, 0x33, 0xd0, 0xc1, 0xb1, 0x49, 0x32, 0x26, 0x99, 0xf0, 0x1d,
        0xb8, 0x67, 0x2b, 0x12, 0xdc, 0xfa, 0xa2, 0x8f, 0x8f, 0x41, 0x23, 0x0d, 0x33, 0xb0, 0x34, 0xe4,
        0x64, 0xcb, 0xec, 0x54, 0xe2, 0x43, 0x85, 0x24, 0x8d, 0x46, 0xcb, 0x2e, 0xfc, 0x4f, 0x22, 0xfc,
        0x63, 0x57, 0x75, 0x8e, 0x97, 0xc1, 0x8e, 0x02, 0x4f, 0x62, 0x65, 0x35, 0xf6, 0x89, 0x45, 0xa6,
        0xc7, 0x0c, 0x28, 0x58, 0xbf, 0x74, 0x9f, 0x5f, 0x08, 0xcf, 0x69, 0x0c, 0x2a, 0x54, 0xbe, 0xd7,
        0x38, 0xf7, 0xac, 0x20, 0x18, 0x96, 0x22, 0xbe, 0x2f, 0x1d, 0x83, 0xe3, 0x97, 0xb5, 0x02, 0x03,
        0x01, 0x00, 0x01, 0xa3, 0x7f, 0x30, 0x7d, 0x30, 0x7b, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x74,
        0x30, 0x72, 0x82, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
        0x6f, 0x6d, 0x82, 0x0b, 0x2a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f, 0x82,
        0x17, 0x2a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x75, 0x73, 0x65, 0x72, 0x63, 0x6f, 0x6e,
        0x74, 0x65, 0x6e, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0c, 0x2a, 0x2e, 0x67, 0x69, 0x74, 0x68,
        0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
        0x6f, 0x6d, 0x82, 0x09, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f, 0x82, 0x15, 0x67,
        0x69, 0x74, 0x68, 0x75, 0x62, 0x75, 0x73, 0x65, 0x72, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
        0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x0e, 0x67, 0xe7, 0x96, 0x8a, 0xfe, 0xf8, 0x9b,
        0x71, 0x1b, 0xb3, 0xc0, 0x26, 0x3b, 0x51, 0xa8, 0x26, 0x99, 0x88, 0xc9, 0x02, 0x45, 0x6d, 0xe1,
        0x3c, 0x84, 0x59, 0xe1, 0x5b, 0xd0, 0x0d, 0x51, 0x78, 0x4a, 0xe0, 0x22, 0xf6, 0x4e, 0xb9, 0x3f,
        0x19, 0x88, 0xc2, 0x33, 0x37, 0x1f, 0xc0, 0x1a, 0xba, 0xb9, 0x1e, 0x59, 0x63, 0x8d, 0xdb, 0x77,
        0x3b, 0x16, 0x3c, 0x73, 0x48, 0xb6, 0xba, 0x9a, 0x7b, 0x4a, 0xd8, 0xa5, 0x1f, 0xfa, 0x79, 0x60,
        0xb3, 0x71, 0x0c, 0xc2, 0x8f, 0x06, 0xe3, 0xce, 0xae, 0xf5, 0x2f, 0x1f, 0xb8, 0x61, 0x38, 0x70,
        0x3f, 0x49, 0xf8, 0xef, 0xb2, 0x32, 0xec, 0x5f, 0x72, 0xc7, 0xaa, 0x48, 0x70, 0xfc, 0x62, 0x0f,
        0x62, 0x87, 0x11, 0xe1, 0x03, 0xad, 0x9a, 0xf7, 0xfb, 0x87, 0x0e, 0x07, 0xab, 0xc7, 0x1d, 0xf5,
        0x46, 0xb6, 0x2a, 0x6f, 0xac, 0x3c, 0x2e, 0x29, 0x78, 0x0e, 0xf2, 0x64, 0xa4, 0x2d, 0x12, 0x76,
        0xec, 0x4a, 0x70, 0xc2, 0x44, 0x81, 0x82, 0x3d, 0x46, 0x9b, 0xc7, 0xc7, 0x55, 0xd1, 0x3e, 0xd4,
        0x5c, 0x12, 0xa8, 0xd9, 0xe2, 0x63, 0x9e, 0xfa, 0xdf, 0xad, 0xcb, 0x1d, 0xe3, 0x5b, 0x30, 0x69,
        0x0d, 0xd7, 0x51, 0x82, 0xb6, 0xf0, 0x6a, 0x13, 0x18, 0x7b, 0x68, 0x98, 0x36, 0x8f, 0x54, 0x8a,
        0x53, 0x6a, 0x9e, 0x0a, 0xea, 0xc1, 0x66, 0x05, 0xc9, 0x54, 0x5a, 0xe4, 0x74, 0xb4, 0xb8, 0x6c,
        0x94, 0xc3, 0xd4, 0x82, 0x5d, 0x55, 0x85, 0xda, 0xbf, 0x7a, 0x76, 0xbf, 0xaf, 0x2d, 0x98, 0x63,
        0x2c, 0xe5, 0x40, 0xbf, 0x98, 0xe3, 0x5e, 0x8f, 0xf1, 0xcd, 0x12, 0xf8, 0x11, 0x2a, 0xdb, 0xd0,
        0xe8, 0x20, 0x3f, 0x7a, 0xa9, 0x14, 0x0f, 0xa4, 0xa2, 0x78, 0x7b, 0xc7, 0xf4, 0x7f, 0xcc, 0xe3,
        0x43, 0x90, 0x25, 0x3f, 0x90, 0x58, 0xc2, 0x04, 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00,
        0x00
};

// ASK
uint8_t packet7[] = {
        0x45, 0x00, 0x00, 0x28, 0x2b, 0x4a, 0x40, 0x00, 0x40, 0x06, 0xd3, 0x23, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x01, 0xcc, 0x5a, 0x4f, 0x1d, 0xe6,
        0x50, 0x10, 0x02, 0x80, 0x2c, 0x1c, 0x00, 0x00
};

// client key exchange
uint8_t packet8[] = {
        0x45, 0x00, 0x01, 0x66, 0x2b, 0x4b, 0x40, 0x00, 0x40, 0x06, 0xd1, 0xe4, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x01, 0xcc, 0x5a, 0x4f, 0x1d, 0xe6,
        0x50, 0x18, 0x02, 0x80, 0xfb, 0x21, 0x00, 0x00, 0x16, 0x03, 0x03, 0x01, 0x06, 0x10, 0x00, 0x01,
        0x02, 0x01, 0x00, 0xc7, 0x5c, 0x6f, 0xeb, 0x36, 0x0f, 0x60, 0x2d, 0x90, 0xd4, 0x0f, 0x99, 0x51,
        0xf9, 0x1f, 0x2a, 0xfc, 0xfb, 0xd6, 0x40, 0x28, 0x24, 0x3b, 0x39, 0x50, 0x66, 0xd2, 0xe8, 0x71,
        0x9e, 0xf0, 0xcc, 0x77, 0x2f, 0xe4, 0xd2, 0x4a, 0xb0, 0x14, 0x2f, 0xcf, 0xc2, 0xc8, 0x4c, 0x86,
        0x53, 0x55, 0xdf, 0x05, 0x49, 0x79, 0xf5, 0x67, 0x03, 0xde, 0x43, 0x95, 0x7a, 0xeb, 0x3a, 0xc0,
        0xfc, 0x0f, 0x07, 0x85, 0x58, 0x32, 0x6b, 0xf5, 0xe7, 0x7e, 0x1f, 0x5e, 0x42, 0x65, 0xf6, 0x15,
        0x77, 0x5e, 0x6b, 0xdb, 0x1f, 0x02, 0xa8, 0x47, 0xf9, 0xce, 0x90, 0x1a, 0xf2, 0x4c, 0x36, 0xc9,
        0x55, 0x95, 0x15, 0xae, 0xc9, 0xd9, 0xf5, 0x57, 0x53, 0x15, 0x6b, 0x7a, 0x2f, 0xb7, 0x3f, 0x11,
        0xa4, 0xb1, 0x8f, 0x0c, 0xdb, 0x06, 0x03, 0xda, 0x05, 0x44, 0x24, 0xed, 0xa5, 0x64, 0x67, 0x5d,
        0xdd, 0x66, 0x33, 0xa8, 0x93, 0xb6, 0xbe, 0x3a, 0xd8, 0xde, 0x79, 0x02, 0x9b, 0xa9, 0xb4, 0x85,
        0x3b, 0x38, 0xe0, 0x79, 0x4c, 0x11, 0xf6, 0x5e, 0x1d, 0x42, 0xd3, 0x1a, 0x87, 0x61, 0x2f, 0xce,
        0x8a, 0x40, 0xa5, 0x79, 0xa6, 0x25, 0xdc, 0x9b, 0x6c, 0xa3, 0x1d, 0xc3, 0x7d, 0x17, 0xbd, 0x6f,
        0xa7, 0xd8, 0x77, 0x3d, 0x1b, 0x0f, 0x19, 0x5f, 0x09, 0x7c, 0x8f, 0x34, 0x62, 0x7f, 0x76, 0xbb,
        0xc4, 0x1c, 0x43, 0xf0, 0xc7, 0x13, 0x8e, 0x14, 0x8d, 0x66, 0x89, 0x55, 0x3c, 0xa1, 0xd1, 0x02,
        0xc9, 0xff, 0xec, 0x7d, 0xe9, 0x4f, 0x72, 0x28, 0x24, 0x5d, 0xc7, 0xaf, 0x6e, 0xd4, 0x4e, 0xe9,
        0x1f, 0xf7, 0xc1, 0x83, 0xd0, 0xd2, 0x0c, 0xe9, 0x36, 0xb1, 0x0d, 0x27, 0xc7, 0x01, 0x3a, 0x20,
        0x45, 0xce, 0x71, 0x4f, 0x74, 0x2f, 0x9d, 0xee, 0x83, 0xcb, 0xc7, 0x6a, 0x23, 0x27, 0x59, 0x52,
        0x20, 0xce, 0xb6, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x28, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x1e, 0x7e, 0xcf, 0x39, 0x63, 0xc4, 0x5c, 0x8e, 0x5b,
        0xe0, 0x2a, 0xb2, 0x9b, 0x39, 0x85, 0x24, 0xa6, 0x14, 0x31, 0xae, 0xae, 0xec, 0x58, 0xfe, 0x95,
        0xc7, 0xba, 0xa9, 0x20, 0x1d, 0xfd
};

// ASK
uint8_t packet9[] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x3e, 0x6e, 0xb9, 0xc7, 0x6e, 0x99,
        0x0a, 0x01, 0x0a, 0x01, 0x01, 0xbb, 0xda, 0x6a, 0x5a, 0x4f, 0x1d, 0xe6, 0xee, 0xae, 0x03, 0x0a,
        0x50, 0x10, 0x3f, 0x40, 0xee, 0x1d, 0x00, 0x00
};

// change cypher spec
uint8_t packet10[] = {
        0x45, 0x00, 0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x3e, 0x3b, 0xb9, 0xc7, 0x6e, 0x99,
        0x0a, 0x01, 0x0a, 0x01, 0x01, 0xbb, 0xda, 0x6a, 0x5a, 0x4f, 0x1d, 0xe6, 0xee, 0xae, 0x03, 0x0a,
        0x50, 0x10, 0x3f, 0x40, 0x5b, 0xf0, 0x00, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03,
        0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x60, 0xb8, 0x4d, 0x7a,
        0xba, 0x90, 0xf9, 0xd1, 0x97, 0xbd, 0x85, 0x5f, 0xa5, 0x94, 0xb4, 0xf1, 0x8d, 0x90, 0x24, 0x07,
        0x33, 0xa6, 0x0d, 0x83, 0x9c, 0x1d, 0x86, 0xa3, 0x68, 0x22, 0xe1,
};

// ASK
uint8_t packet11[] = {
        0x45, 0x00, 0x00, 0x28, 0x2b, 0x4c, 0x40, 0x00, 0x40, 0x06, 0xd3, 0x21, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x03, 0x0a, 0x5a, 0x4f, 0x1e, 0x19,
        0x50, 0x10, 0x02, 0x80, 0x2a, 0xab, 0x00, 0x00
};

// Application data
uint8_t packet12[] = {
        0x45, 0x00, 0x00, 0xbf, 0x2b, 0x4d, 0x40, 0x00, 0x40, 0x06, 0xd2, 0x89, 0x0a, 0x01, 0x0a, 0x01,
        0xb9, 0xc7, 0x6e, 0x99, 0xda, 0x6a, 0x01, 0xbb, 0xee, 0xae, 0x03, 0x0a, 0x5a, 0x4f, 0x1e, 0x19,
        0x50, 0x18, 0x02, 0x80, 0x3c, 0xe1, 0x00, 0x00, 0x17, 0x03, 0x03, 0x00, 0x92, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x3c, 0xc0, 0x24, 0x67, 0xd7, 0x5c, 0x3a, 0x75, 0x80, 0xb3, 0xa2,
        0x41, 0xf7, 0x06, 0xf2, 0xa9, 0xfc, 0xd4, 0xb8, 0xbd, 0xb5, 0xe3, 0x92, 0xdd, 0x40, 0xb0, 0xad,
        0x0c, 0x22, 0x9c, 0xac, 0xad, 0xd8, 0xcb, 0xa7, 0xe6, 0xd4, 0xc2, 0x70, 0xd5, 0xc9, 0x6f, 0xbb,
        0x40, 0x54, 0x41, 0xf2, 0x21, 0xaf, 0xbc, 0x7b, 0x68, 0x68, 0x33, 0xde, 0xfa, 0x3f, 0xeb, 0x38,
        0x62, 0x27, 0x8c, 0x92, 0x15, 0x24, 0x98, 0x87, 0xe0, 0xf4, 0x26, 0x54, 0x10, 0xe8, 0x8a, 0x06,
        0xb9, 0x56, 0xa1, 0x52, 0x80, 0x2e, 0xab, 0x27, 0xf7, 0x01, 0x13, 0x41, 0x53, 0xea, 0xaa, 0x3c,
        0xbe, 0x5b, 0x56, 0xa9, 0x5c, 0xbf, 0xfb, 0xfe, 0x7c, 0x02, 0xa0, 0xb1, 0xcb, 0x62, 0x59, 0xc5,
        0x82, 0xc0, 0xd6, 0x14, 0x83, 0xef, 0x0a, 0xdc, 0x6b, 0xa5, 0x98, 0xba, 0xd8, 0xb2, 0x28, 0x33,
        0xa9, 0x01, 0x33, 0xdc, 0x7d, 0x56, 0x85, 0xce, 0x6f, 0xd3, 0x7d, 0x65, 0xbc, 0xa6, 0xb5
};

// ASK
const uint8_t packet13[] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x3e, 0x6e, 0xb9, 0xc7, 0x6e, 0x99,
        0x0a, 0x01, 0x0a, 0x01, 0x01, 0xbb, 0xda, 0x6a, 0x5a, 0x4f, 0x1e, 0x19, 0xee, 0xae, 0x03, 0xa1,
        0x50, 0x10, 0x3f, 0x40, 0xed, 0x53, 0x00, 0x00
};

const char tls_key_log[] = "CLIENT_RANDOM A08237C6CC3DB90E6CFECFB5CB269B8F84DB5F21786D750E68E003FF8E18B7B4 1F472D89F6D226F4DD2F230523DDE4ED450C815EE84BBBF94BC991E55378494E91AD52086407939CA7FB7EA9934516E3";

int main() {
    FILE *p_file = NULL;
    uint8_t buffer[10000]; // for brevity's sake

    if (NULL == (p_file = fopen("test.pcapng", "w"))) {
        printf("failed to open file for the pcapng file\n");
        return -1;
    }

    fwrite(buffer, 1, pcapng_write_section_header_block(buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_network_interfaces_description_block(10000, buffer, sizeof(buffer)), p_file);

    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet1, sizeof(packet1), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet2, sizeof(packet2), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet3, sizeof(packet3), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet4, sizeof(packet4), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet5, sizeof(packet5), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet6, sizeof(packet6), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet7, sizeof(packet7), buffer, sizeof(buffer)), p_file);

    fwrite(buffer, 1, pcapng_write_decryption_secrets_block(tls_key_log, sizeof(tls_key_log), buffer, sizeof(buffer)), p_file);

    // these packets can be decrypted
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet8, sizeof(packet8), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet9, sizeof(packet9), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet10, sizeof(packet10), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet11, sizeof(packet11), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet12, sizeof(packet12), buffer, sizeof(buffer)), p_file);
    fwrite(buffer, 1, pcapng_write_enhanced_packet_block(packet13, sizeof(packet13), buffer, sizeof(buffer)), p_file);

    fflush(p_file);
    fclose(p_file);

    return 0;
}