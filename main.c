#include <pcap.h>
#include <stdio.h>
#include "arp.h"

void usage(const char *exe) {
    fprintf(stderr, "Usage : %s <Interface> <Sender IP> <Target IP>\n", exe);
}

int main(int argc, char* argv[]) {
    if(argc != 4) {
        usage(argv[0]);
        return -1;
    }
    // 0. Opening Device (interface)
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    bpf_u_int32 net, mask;  // local IP, netmask
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[-] Can't get netmask for device [%s] : %s\n", dev, errbuf);
        return -1;
    }
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "[-] Can't open device %s : %s\n", dev, errbuf);
        return -1;
    }

    // 1. Get HW(MAC) address of local machine

    BYTE hw_addr[HW_ADDR_LEN];
    char hw_addr_str[(HW_ADDR_LEN<<1)+1];

    get_hw_addr(hw_addr, dev);
    addr_to_str(hw_addr_str, "Attacker MAC", hw_addr);

    // 2. Get Sender IP address

    BYTE snd_hw_addr[HW_ADDR_LEN];
    char snd_hw_addr_str[(HW_ADDR_LEN<<1)+1];

    if(get_sender_IP(snd_hw_addr, handle, (const char *)hw_addr_str, net) == -1) {
        fprintf(stderr, "[-] Error while fetching the target IP\n");
    }
    addr_to_str(snd_hw_addr_str, "SENDER MAC", snd_hw_addr);

    pcap_close(handle);
    return 0;
}