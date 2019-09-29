#pragma once
#include <pcap.h>

#define HW_ADDR_LEN 6

// Type definition for convenience
typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;

void get_hw_addr(BYTE *hw_addr, const char *dev);