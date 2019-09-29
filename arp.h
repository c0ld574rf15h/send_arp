#pragma once
#include <pcap.h>

// Const value used in program
#define HW_ADDR_LEN     6
#define IP_ADDR_LEN     4
#define FLTR_SZ_MAX     40
#define SIZE_ETHERNET   14

// Type definition for convenience
typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;

// pcap struct
typedef struct arp_fmt {
    // Hardware Type | Protocol Type
    WORD hw_type, proto_type;
    // HW address length | Proto address length | OPcode
    BYTE hw_addr_len, proto_addr_len;
    WORD opcode;
    // Sender HW address | Sender Proto address
    BYTE snd_hw_addr[HW_ADDR_LEN], snd_proto_addr[IP_ADDR_LEN];
    // Target HW address | Target Proto address
    BYTE trg_hw_addr[HW_ADDR_LEN], trg_proto_addr[IP_ADDR_LEN];
} ARP;

void addr_to_str(char *addr_str, const char* msg, const BYTE *addr);
void handle_pcap_next(int res, struct pcap_pkthdr *hdr);
void get_hw_addr(BYTE *hw_addr, const char *dev);
int get_sender_IP(BYTE *sender_IP, pcap_t *handle, const char *attacker_hw_addr, bpf_u_int32 net);