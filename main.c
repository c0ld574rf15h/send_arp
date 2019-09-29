#include <pcap.h>
#include <stdio.h>
#include "arp.h"

void usage(const char *exe) {
    fprintf(stderr, "Usage : %s <Interface> <Sender IP> <Target IP>");
}

int main(int argc, char* argv[]) {
    if(argc != 4) {
        usage(argv[0]);
        return -1;
    }
    // 0. Opening Device (interface)
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        return -1;
    }
    // 1. Get HW(MAC) address of local machine
    BYTE hw_addr[HW_ADDR_LEN];
    get_hw_addr(hw_addr, dev);

    pcap_close(handle);
    return 0;
}