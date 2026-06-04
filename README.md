# Gift IDS

Gift IDS is a learning-focused IDS/network security monitoring tool written in
C. It captures Ethernet frames, parses IPv4 TCP/UDP/ICMP packets, prints packet
summaries, logs valid packet events, and raises simple beginner-friendly alerts.

## Project Structure

```text
src/
  main.c
  capture.c
  parser.c
  logger.c
  detector.c

include/
  capture.h
  parser.h
  logger.h
  detector.h

logs/
  giftids.log
  giftids_alerts.log

Makefile
```

## Build

```sh
make
```

## Run

Packet capture uses Linux raw sockets, so it requires root or the `CAP_NET_RAW`
capability.

```sh
sudo ./giftids
sudo ./giftids -i eth0
sudo ./giftids -i wlan0 -c 20
```

Options:

- `-i <interface>`: capture on a specific interface.
- `-c <count>`: stop after capturing this many raw frames. The default is to
  run until interrupted with `Ctrl+C`.
- `-h`: show help.

## Sample Output

```text
[2026-06-05 10:22:31] frame_len=74 IPv4 192.168.1.5 -> 8.8.8.8 proto=UDP ttl=64 ip_len=60 sport=55320 dport=53
[2026-06-05 10:22:34] frame_len=66 IPv4 192.168.1.8 -> 192.168.1.1 proto=TCP ttl=64 ip_len=52 sport=52044 dport=443 flags=SYN,ACK
[2026-06-05 10:22:40] frame_len=98 IPv4 192.168.1.10 -> 8.8.8.8 proto=ICMP ttl=64 ip_len=84 icmp_type=8 icmp_code=0
[ALERT] LOW TCP SYN Watch 192.168.1.4 -> 192.168.1.1 TCP SYN connection attempt detected
```

## Logs

Packet events are saved here:

```text
logs/giftids.log
```

Example packet log:

```text
[2026-06-05 10:22:31] frame_len=74 IPv4 192.168.1.5 -> 8.8.8.8 proto=UDP ttl=64 ip_len=60 sport=55320 dport=53
```

Alerts are saved separately here:

```text
logs/giftids_alerts.log
```

Example alert log:

```text
[2026-06-05 14:20:44] [ALERT] severity=LOW type="TCP SYN Watch" src=192.168.1.4 dst=192.168.1.1 message="TCP SYN connection attempt detected"
```

## Phase 4 Detection Rules

Phase 4 adds a small stateless detection engine. A detection rule is a simple
condition that checks parsed packet fields and returns an alert when the packet
looks interesting.

Implemented rules:

- Suspicious Port: alerts on traffic to TCP/UDP destination ports 21, 22, 23,
  25, 53, 110, 139, 143, 445, and 3389. These ports are flagged because they
  are common service ports that are often probed during basic reconnaissance.
- ICMP Echo Request: alerts on ICMP type 8. Ping traffic is normal, but it is
  useful to observe because simple host discovery can use echo requests.
- TCP SYN Watch: alerts on TCP packets with SYN set and ACK not set. A SYN
  packet usually represents a new TCP connection attempt.

This phase is stateless: each packet is analyzed by itself. Gift IDS does not
yet count packets over time, detect port scans, detect floods, block traffic, or
perform advanced attack detection.

## Notes

Current scope:

- Phase 2 packet parser for Ethernet, IPv4, TCP, UDP, and ICMP
- Phase 3 logging engine that appends to `logs/giftids.log`
- Phase 4 basic detection rules that append alerts to `logs/giftids_alerts.log`

Future phases can add:

- add packet counters and protocol statistics
- add simple signatures, such as suspicious port scans
- add IPv6 parsing
- add a rule format for detection logic
