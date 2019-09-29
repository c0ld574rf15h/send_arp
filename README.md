### send_arp

---

Toy project for transmitting fraud ARP packet to specified host
- **sender** : the Victim
- **target** : the LAN gateway (usually...)

**Usage**
```
$ ./send_arp <interface> <sender_IP> <target_IP>
```

[Example]
```
$ ./send_arp eth0 192.168.10.8 192.160.10.1
```