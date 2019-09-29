#include "arp.h"
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

WORD my_ntohs(WORD w) {
    return ((w & 0x00FF) << 8) | ((w & 0xFF00) >> 8);
}

void parse_bytes(BYTE *bytes, char sep, const char *str, int size, int base) {
    for(int i=0;i<size;++i) {
        bytes[i] = strtoul(str, NULL, base);
        str = strchr(str, sep);
        if(str == NULL || *str == '\0') break;
        str += 1;
    }
}

void addr_to_str(char *addr_str, const char* msg, const BYTE *addr) {
    for(int i=0;i<HW_ADDR_LEN;++i)
        sprintf(&addr_str[i<<1], "%02X", addr[i]);
    addr_str[HW_ADDR_LEN<<1] = '\0';
    printf("[+] %s : %s\n", msg, addr_str);
}

void handle_pcap_next(int res, struct pcap_pkthdr *hdr) {
    switch(res) {
        case 0:
            fprintf(stderr, "[!] Timeout Expired\n");
            break;
        case PCAP_ERROR:
            fprintf(stderr, "[!] Error occured while reading packet\n");
            break;
        case PCAP_ERROR_BREAK:	// Not used from this project
            fprintf(stderr, "[!] No more packets to read from savefile\n");
            break;
        case 1:
            printf("[*] %d Bytes Captured\n", hdr->caplen);
    }
}

void send_arp_packet(pcap_t *handle, int opcode, BYTE *snd_hw, BYTE *snd_ip, BYTE *trg_hw, BYTE *trg_ip) {
    const BYTE *BROADCAST = "\xFF\xFF\xFF\xFF\xFF\xFF";
    const BYTE *NULL_ADDR = "\x00\x00\x00\x00\x00\x00";
    
    // FILL ETHERNET FIELD
    ETH eth;
    memcpy(eth.dst_hw_addr, (opcode == REQ) ? BROADCAST : trg_hw, HW_ADDR_LEN);
    memcpy(eth.src_hw_addr, snd_hw, HW_ADDR_LEN);
    eth.ether_type = my_ntohs(ARP_TYPE);

    // FILL ARP FIELD
    ARP arp;
    arp.hw_type = my_ntohs(ETH_TYPE); arp.proto_type = my_ntohs(IPv4_TYPE);
    arp.hw_addr_len = HW_ADDR_LEN; arp.proto_addr_len = IP_ADDR_LEN;
    arp.opcode = my_ntohs(opcode);
    memcpy(arp.snd_hw_addr, snd_hw, HW_ADDR_LEN);
    memcpy(arp.snd_proto_addr, snd_ip, IP_ADDR_LEN);
    memcpy(arp.trg_hw_addr, (opcode == REQ) ? NULL_ADDR : trg_hw, HW_ADDR_LEN);
    memcpy(arp.trg_proto_addr, trg_ip, IP_ADDR_LEN);

    ARP_PKT pkt = { eth, arp };
    if(pcap_sendpacket(handle, (const u_char*)&pkt, sizeof(pkt)) != 0)
        fprintf(stderr, "[-] Error while sending ARP packet\n");
}

void get_hw_ip_addr(BYTE *hw_addr, BYTE *ip_addr, const char *dev) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);

    // GET HARDWARE ADDRESS
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(hw_addr, ifr.ifr_hwaddr.sa_data, HW_ADDR_LEN);

    // GET IP ADDRESS
    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(ip_addr, ifr.ifr_addr.sa_data+2, IP_ADDR_LEN);
}

int set_pcap_filter(pcap_t *handle, const char *attacker_hw_addr_str, bpf_u_int32 net) {
    struct bpf_program fp;
    char filter[FLTR_SZ_MAX] = "ether proto 0x0806 and ether dst ";
    strcat(filter, attacker_hw_addr_str);

    if(pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "[-] Can't parse filter \'%s\'\n==> %s\n", filter, pcap_geterr(handle));
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Can't install filter \'%s\'\n==>%s\n", filter, pcap_geterr(handle));
        return -1;
    }
}

int get_sender_MAC(BYTE * snd_hw_addr, pcap_t *handle) {
    struct pcap_pkthdr *header;
    const BYTE *data;

    int res = pcap_next_ex(handle, &header, &data);
    handle_pcap_next(res, header);

    ARP *arp = (ARP *)(data + SIZE_ETHERNET);
    memcpy(snd_hw_addr, arp->snd_hw_addr, HW_ADDR_LEN);
}