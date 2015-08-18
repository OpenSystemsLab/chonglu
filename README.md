# Chống Lũ - SYN Flood Stopper
(Chống Lũ means anti-flooding in Vietnamese)


Chống Lũ listens and parses incoming packets on NIC, an IP will get blocked (via ipset) if it made too many SYN requests per second without ACK.

We use [PF_RING](https://github.com/rgv151/pfring.nim) for capturing packets, and [libipset](https://github.com/rgv151/ipset.nim) for blocking zoombies.

## W.I.P.