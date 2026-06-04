# IDS Packet Sniffer

A tiny Linux packet sniffer written in C. It captures Ethernet frames from a
network interface and prints basic details for IPv4 TCP, UDP, and ICMP packets.

## Build

```sh
make
```

## Run

Packet capture through raw sockets requires root or the `CAP_NET_RAW`
capability.

```sh
sudo ./ids_sniffer
sudo ./ids_sniffer -i eth0
sudo ./ids_sniffer -i wlan0 -c 20
```

Options:

- `-i <interface>`: capture on a specific interface.
- `-c <count>`: stop after capturing this many packets. The default is to run
  until interrupted with `Ctrl+C`.
- `-h`: show help.

## Notes

This is an early IDS foundation. Good next steps are:

- add packet counters and protocol statistics
- add simple signatures, such as suspicious port scans
- log alerts to a file
- add IPv6 parsing
- add a rule format for detection logic
