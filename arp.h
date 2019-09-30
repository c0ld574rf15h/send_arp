#pragma once
#include <pcap.h>

// Type definition for convenience
typedef uint8_t     BYTE;
typedef uint16_t    WORD;
typedef uint32_t    DWORD;

// Const value used in program
#define HW_ADDR_LEN     6
#define IP_ADDR_LEN     4
#define FLTR_SZ_MAX     100
#define SIZE_ETHERNET   14
#define ARP_TYPE        0x0806
#define ETH_TYPE        0X0001
#define IPv4_TYPE       0x0800
#define REQ             1
#define REP             2


// pcap struct
typedef struct eth_fmt {
    // Destination HW address
    BYTE dst_hw_addr[HW_ADDR_LEN];
    // Source HW address
    BYTE src_hw_addr[HW_ADDR_LEN];
    // Ether type
    WORD ether_type;
} ETH;

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

typedef struct arp_packet {
    ETH eth_field;
    ARP arp_field;
} ARP_PKT;


// functions
WORD my_ntohs(WORD w);
void parse_bytes(BYTE *bytes, char sep, const char *str, int size, int base);
void addr_to_str(char *addr_str, const char* msg, const BYTE *addr);
void handle_pcap_next(int res, struct pcap_pkthdr *hdr);
int set_pcap_filter(pcap_t *handle, const char *attacker_hw_addr_str, bpf_u_int32 net);

void send_arp_packet(pcap_t *handle, int opcode, BYTE *snd_hw, BYTE *snd_ip, BYTE *trg_hw, BYTE *trg_ip);
void get_hw_ip_addr(BYTE *hw_addr, BYTE *ip_addr, const char *dev);
int get_sender_MAC(BYTE * snd_hw_addr, pcap_t *handle);
