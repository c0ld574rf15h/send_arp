#include "arp.h"
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

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

void get_hw_addr(BYTE *hw_addr, const char *dev) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);  // GET HARDWARE ADDRESS
    memcpy(hw_addr, ifr.ifr_hwaddr.sa_data, HW_ADDR_LEN);
}

int get_sender_IP(BYTE *sender_hw_addr, pcap_t *handle, const char *attacker_hw_addr, bpf_u_int32 net) {
    struct bpf_program fp;
    char filter[FLTR_SZ_MAX] = "ether proto 0x0806 and ether dst ";
    strcat(filter, attacker_hw_addr);

    if(pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "[-] Can't parse filter \'%s\'\n==> %s\n", filter, pcap_geterr(handle));
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Can't install filter \'%s\'\n==>%s\n", filter, pcap_geterr(handle));
        return -1;
    }

    struct pcap_pkthdr *header;
    const BYTE *data;

    puts("[*] Waiting for ARP reply...");
    int res = pcap_next_ex(handle, &header, &data);
    handle_pcap_next(res, header);

    ARP *arp = (ARP *)(data + SIZE_ETHERNET);
    memcpy(sender_hw_addr, arp->snd_hw_addr, HW_ADDR_LEN);
    return 0;
}