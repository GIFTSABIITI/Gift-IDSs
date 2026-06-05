# Gift IDS

Gift IDS is a learning-focused intrusion detection and network monitoring tool
written in C. It captures Ethernet frames, parses IPv4 TCP/UDP/ICMP packets,
logs packet events, raises beginner-friendly alerts, and prints runtime
statistics from the terminal.

## Project Structure

```text
src/
  main.c
  capture.c
  parser.c
  logger.c
  detector.c
  config.c
  cli.c
  stats.c

include/
  capture.h
  parser.h
  logger.h
  detector.h
  config.h
  cli.h
  stats.h

config/
  giftids.conf

logs/
  giftids.log
  giftids_alerts.log

Makefile
```

## Features

Current phases:

- Phase 1: live packet capture with Linux raw sockets
- Phase 2: Ethernet, IPv4, TCP, UDP, and ICMP parsing
- Phase 3: packet event logging
- Phase 4: basic stateless detection rules
- Phase 5: stateful detection with time windows
- Phase 6: configuration file support
- Phase 7: improved command-line interface
- Phase 8: runtime statistics dashboard

Gift IDS does not implement GUI, web dashboards, database storage, packet
blocking/IPS, AI, or advanced threat intelligence.

## Detection Rules

Stateful rules:

- Possible SYN Flood: HIGH severity for many TCP SYN packets without ACK from
  one source to the same destination IP and destination port.
- Possible Port Scan: MEDIUM severity for many unique TCP destination ports
  contacted by one source on the same destination IP.
- Possible ICMP Flood: MEDIUM severity for many ICMP echo requests from one
  source to the same destination IP.

Stateless rules:

- Suspicious Port
- ICMP Echo Request
- TCP SYN Watch

Stateful detection keeps short-lived memory about recent packets. Time windows
matter because ten packets in one day and ten packets in ten seconds mean very
different things. Cooldowns reduce repeated alerts for the same behavior.

## Configuration

Gift IDS loads defaults first, then `config/giftids.conf`, then CLI overrides.
CLI overrides take priority so a single lab run can change logs or output mode
without editing the config file.

Default config:

```text
port_scan_threshold=10
port_scan_window_seconds=10
syn_flood_threshold=30
syn_flood_window_seconds=10
icmp_flood_threshold=20
icmp_flood_window_seconds=10
alert_cooldown_seconds=10
packet_log_file=logs/giftids.log
alert_log_file=logs/giftids_alerts.log
```

Empty lines and lines starting with `#` are ignored. Unknown keys, malformed
lines, and invalid values produce warnings but do not stop the IDS.

## Build

```sh
make
```

The build uses `-Wall -Wextra -g`. Gift IDS currently uses Linux raw sockets, so
no libpcap link flag is needed.

## CLI

```text
Gift IDS - Learning-focused intrusion detection system

Usage:
  giftids --interface <name> [options]

Options:
  --interface <name>       Network interface to capture from
  --config <path>          Config file path
  --packet-log <path>      Override packet log path
  --alert-log <path>       Override alert log path
  --stats                  Show live statistics
  --no-packet-log          Disable packet event logging
  --no-alert-log           Disable alert logging
  --verbose                Print detailed packet output
  --quiet                  Print only alerts and important messages
  --help                   Show this help message
  --version                Show version information
```

Version:

```sh
./giftids --version
```

Output:

```text
Gift IDS version 0.8.0
```

## Run

Packet capture uses Linux raw sockets, so it requires root or the `CAP_NET_RAW`
capability.

```sh
sudo ./giftids --interface wlan0
sudo ./giftids --interface eth0 --stats
sudo ./giftids --interface wlan0 --config config/giftids.conf --verbose
sudo ./giftids --interface eth0 --packet-log logs/lab_packets.log --alert-log logs/lab_alerts.log
sudo ./giftids --interface eth0 --no-packet-log --no-alert-log --quiet --stats
```

Legacy aliases still work:

```sh
sudo ./giftids -i eth0 -c 20
```

## Output Modes

Default mode prints normal packet summaries and alerts.

`--verbose` prints detailed packet output, including TCP flags, ICMP type/code,
TTL, IP length, and frame length.

`--quiet` suppresses normal packet summaries. Alerts, important messages, live
stats, and final summaries still print.

Packet logging and alert logging can be disabled separately with
`--no-packet-log` and `--no-alert-log`. If disabled, the related log function
does nothing safely.

## Statistics

`--stats` prints live statistics every 5 seconds. Runtime statistics help users
see whether the IDS is receiving traffic, which protocols are most common, how
many bytes were seen, and whether alerts are rare or frequent.

Example live stats:

```text
================ Gift IDS Live Stats ================
Runtime: 00:02:15
Packets captured: 12450
Valid packets: 12190
Invalid packets: 260
TCP: 8000 | UDP: 3500 | ICMP: 690 | Other: 0
Bytes seen: 9.4 MB
Alerts: 8
Low: 5 | Medium: 2 | High: 1
Top alert types:
  Suspicious Port: 3
  TCP SYN Watch: 2
  Possible Port Scan: 1
  Possible SYN Flood: 1
  Possible ICMP Flood: 1
=====================================================
```

When capture exits, Gift IDS prints a final summary:

```text
================ Gift IDS Final Summary ================
Runtime: 00:10:42
Packets captured: 53120
Valid packets: 52600
Invalid packets: 520
TCP packets: 32100
UDP packets: 18400
ICMP packets: 2100
Other packets: 0
Bytes seen: 42.8 MB
Total alerts: 19
Low alerts: 11
Medium alerts: 6
High alerts: 2
========================================================
```

Graceful shutdown matters because Ctrl+C should stop packet capture, flush and
close log files, then print the final summary cleanly.

## Logs

Packet events are saved to the configured packet log file by default:

```text
logs/giftids.log
```

Example packet log:

```text
[2026-06-05 10:22:31] frame_len=74 IPv4 192.168.1.5 -> 8.8.8.8 proto=UDP ttl=64 ip_len=60 sport=55320 dport=53
```

Alerts are saved to the configured alert log file by default:

```text
logs/giftids_alerts.log
```

Example alert log:

```text
[2026-06-05 14:21:10] [ALERT] severity=HIGH type="Possible SYN Flood" src=192.168.1.20 dst=192.168.1.10 message="Source sent 30 SYN packets to target port within 10 seconds"
```

## Safe Testing

Test only on systems and local lab networks you own or have explicit permission
to monitor.

Safe checks:

- Generate normal web or DNS traffic and confirm packet logging still works.
- Use simple local connectivity checks to observe ICMP echo request alerts.
- Use controlled lab traffic to verify that alerts appear only after configured
  thresholds are reached.

Do not test against public networks or systems you do not control.
