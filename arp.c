#include "arp.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

void get_hw_addr(BYTE *hw_addr, const char *dev) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);  // GET HARDWARE ADDRESS
    memcpy(hw_addr, ifr.ifr_hwaddr.sa_data, HW_ADDR_LEN);
}