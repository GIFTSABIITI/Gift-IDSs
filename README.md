# Gift IDS

Gift IDS is a learning-focused intrusion detection and network security
monitoring tool written in C. It captures live Ethernet frames, parses IPv4
TCP/UDP/ICMP packets, logs packet events, raises beginner-friendly alerts, reads
saved PCAP files, prints runtime statistics, generates session reports, and can
stream packet and alert events as JSON lines from the terminal.

Gift IDS does not implement a GUI, web dashboard, database storage, IPS/blocking,
AI detection, or advanced threat intelligence yet.

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
  processor.c
  pcap_reader.c
  report.c
  json_output.c

include/
  capture.h
  parser.h
  logger.h
  detector.h
  config.h
  cli.h
  stats.h
  processor.h
  pcap_reader.h
  report.h
  json_output.h

config/
  giftids.conf

logs/
  README.md

reports/
  README.md

samples/
  README.md

tests/
  test_utils.h
  run_tests.c
  test_config.c
  test_detector.c
  test_parser.c
  test_cli.c
  test_stats.c
  test_report.c
  test_json_output.c
```

## Current Phases

- Phase 1: live packet capture with Linux raw sockets
- Phase 2: Ethernet, IPv4, TCP, UDP, and ICMP parsing
- Phase 3: packet event logging
- Phase 4: basic stateless detection rules
- Phase 5: stateful detection with time windows
- Phase 6: configuration file support
- Phase 7: improved command-line interface
- Phase 8: live statistics and final summary
- Phase 9: testing and validation with a small C test harness
- Phase 10: offline PCAP file analysis mode
- Phase 11: detection rule enable/disable configuration
- Phase 12: better alert evidence and investigation recommendations
- Phase 13: final session report generation in text or JSON
- Phase 14: terminal JSON output mode for packet, alert, stats, and completion events

## Build

```sh
make
```

The build uses `-Wall -Wextra -g`. PCAP files are read by a small built-in
classic-PCAP reader, so no external libpcap dependency is required.

## Run Live Mode

Packet capture uses Linux raw sockets, so it requires root or `CAP_NET_RAW`.

```sh
sudo ./giftids --interface wlan0 --stats
sudo ./giftids --interface eth0 --verbose
sudo ./giftids --interface eth0 --packet-log logs/lab_packets.log --alert-log logs/lab_alerts.log
sudo ./giftids --interface eth0 --no-packet-log --no-alert-log --quiet --stats
sudo ./giftids --interface wlan0 --stats --report reports/live_report.txt
sudo ./giftids --interface wlan0 --json
```

If no interface is supplied, Gift IDS keeps the existing raw socket behavior and
captures from the raw socket without binding to one interface.

## Run PCAP Mode

PCAP mode is useful for repeatable IDS testing because the same packet file can
be analyzed again after parser, detector, or config changes.

```sh
./giftids --read samples/test.pcap --stats
./giftids --read samples/test.pcap --quiet
./giftids --read samples/test.pcap --verbose
./giftids --read samples/test.pcap --config config/giftids.conf
./giftids --read samples/test.pcap --report reports/pcap_report.txt
./giftids --read samples/test.pcap --report reports/pcap_report.json --report-format json
./giftids --read samples/test.pcap --json --quiet
```

`--interface` and `--read` are mutually exclusive. Live and offline packets use
the same `processor.c` pipeline: parse, update stats, print/log the packet, run
detection, print/log alerts, and update alert stats.

Example PCAP output:

```text
Analyzing PCAP file 'samples/test.pcap'.
[2026-06-06 10:15:22] IPv4 192.168.1.10 -> 192.168.1.20 proto=TCP sport=51514 dport=445
[ALERT] MEDIUM Suspicious Port 192.168.1.10 -> 192.168.1.20 evidence="Destination port 445 is commonly associated with SMB traffic."
Analyzed 1 packet from 'samples/test.pcap'.
```

## Reports

Use `--report <path>` to generate a final session report after live capture
stops or after PCAP analysis finishes. Reports are useful after a monitoring
session because they preserve the runtime summary, alert counts, rule settings,
log paths, and recommended next steps in one file.

```sh
sudo ./giftids --interface wlan0 --stats --report reports/session_report.txt
./giftids --read samples/test.pcap --report reports/pcap_report.txt
./giftids --read samples/test.pcap --report reports/pcap_report.json --report-format json
```

Supported report formats are `txt` and `json`. The default is `txt`.

Text report example:

```text
Gift IDS Session Report
=======================

Generated At:
- 2026-06-07 15:55:00

Runtime Summary:
- Packets captured: 5000
- Total alerts: 12

Recommendations:
- Review high severity alerts first.
- Use PCAP mode for repeatable testing.
```

JSON report example:

```json
{
  "project": "Gift IDS",
  "report_type": "session_report",
  "run_mode": "pcap_read",
  "runtime_summary": {
    "total_packets": 5000
  },
  "alert_summary": {
    "total_alerts": 12
  }
}
```

## JSON Output

Use `--json` to print terminal events as JSON lines. JSON lines are better for
streaming output because each line is one complete object, which makes the
stream easier for automation, shell tools, and SIEM-style collectors to parse.
Log files remain normal text in this phase.

```sh
sudo ./giftids --interface wlan0 --json
./giftids --read samples/test.pcap --json
./giftids --read samples/test.pcap --json --quiet
./giftids --read samples/test.pcap --json --verbose
```

With `--json --quiet`, packet events are suppressed but alert and completion
events still print. With `--json --stats`, stats are printed as JSON events so
human stats text does not break the JSON-line stream.

JSON packet example:

```json
{"event_type":"packet","timestamp":"2026-06-07 16:05:00","src_ip":"192.168.1.5","dst_ip":"8.8.8.8","protocol":"UDP","src_port":55320,"dst_port":53,"ttl":64,"ip_len":60,"frame_len":74}
```

JSON alert example:

```json
{"event_type":"alert","timestamp":"2026-06-07 16:05:04","severity":"MEDIUM","type":"Possible Port Scan","src_ip":"192.168.1.20","dst_ip":"192.168.1.10","protocol":"TCP","src_port":51544,"dst_port":80,"observed_count":12,"unique_ports":12,"threshold":10,"window_seconds":10,"evidence":"Source contacted 12 unique destination ports on the same target within 10 seconds.","recommendation":"Investigate the source host and verify whether port scanning or service discovery was authorized."}
```

JSON completion example:

```json
{"event_type":"session_complete","timestamp":"2026-06-07 16:10:30","runtime_seconds":42,"total_packets":5000,"total_alerts":12}
```

## Tests

Run all tests:

```sh
make test
```

The tests are intentionally small and dependency-free. Detector tests create
fake `PacketInfo` structs so rule behavior can be tested without live traffic.
Parser tests use raw packet byte arrays because parser safety depends on exact
header lengths and offsets. Config tests protect against bad user input, and
stats tests make sure counters stay reliable as the IDS evolves.

Example test output:

```text
Building Gift IDS tests...
Running tests...
[PASS] config defaults
[PASS] TCP SYN Watch rule
[PASS] parser Ethernet IPv4 TCP
Tests run: 53
Passed: 53
Failed: 0
```

## Detection Rules

Priority order:

1. Possible SYN Flood
2. Possible Port Scan
3. Possible ICMP Flood
4. Suspicious Port
5. ICMP Echo Request
6. TCP SYN Watch

Stateful rules keep short-lived memory about recent packets. Time windows matter
because ten packets in one day and ten packets in ten seconds mean very
different things. Cooldowns reduce repeated alerts for the same source, target,
rule type, and destination port.

Alerts include evidence and a recommendation. Evidence records why the rule
fired, such as a destination port, observed count, threshold, unique port count,
or time window. Recommendations help with investigation by suggesting what to
verify next instead of leaving the analyst with only an alert name.

Verbose alert example:

```text
[ALERT]
Severity: MEDIUM
Type: Possible Port Scan
Source: 192.168.1.20
Destination: 192.168.1.10
Protocol: TCP
Observed Count: 12
Unique Ports: 12
Threshold: 10
Window: 10 seconds
Evidence: Source contacted 12 unique destination ports on the same target within 10 seconds.
Recommendation: Investigate the source host and verify whether port scanning or service discovery was authorized.
```

## Rule Configuration

All rules are enabled by default. Rule enable/disable settings live in
`config/giftids.conf` and accept `true`/`false`, `yes`/`no`, or `1`/`0`.
Disabling noisy learning rules can be useful in labs where you want to focus on
stateful behavior without seeing every ping or TCP SYN connection attempt.

Example:

```text
enable_suspicious_port_rule=true
enable_tcp_syn_watch_rule=false
enable_icmp_echo_rule=false
enable_port_scan_detection=true
enable_syn_flood_detection=true
enable_icmp_flood_detection=true
```

Optional CLI rule disables are also available and are applied after the config
file loads:

```sh
./giftids --read samples/test.pcap --disable-icmp-echo --disable-syn-watch
```

## Example Config

```text
port_scan_threshold=10
port_scan_window_seconds=10

syn_flood_threshold=30
syn_flood_window_seconds=10

icmp_flood_threshold=20
icmp_flood_window_seconds=10

alert_cooldown_seconds=10

enable_suspicious_port_rule=true
enable_tcp_syn_watch_rule=true
enable_icmp_echo_rule=true
enable_port_scan_detection=true
enable_syn_flood_detection=true
enable_icmp_flood_detection=true

packet_log_file=logs/giftids.log
alert_log_file=logs/giftids_alerts.log
```

Unknown keys, malformed lines, invalid numbers, and invalid booleans produce
warnings but do not stop the IDS. Validating config values matters because a
bad threshold or typo should not silently make detection unreliable.

## CLI

```text
Usage:
  giftids --interface <name> [options]
  giftids --read <pcap_file> [options]

Options:
  --interface <name>       Network interface to capture from
  --read <pcap_file>       Analyze packets from a saved PCAP file
  --config <path>          Config file path
  --packet-log <path>      Override packet log path
  --alert-log <path>       Override alert log path
  --report <path>          Generate a final session report
  --report-format <format> Report format: txt or json
  --stats                  Show live statistics
  --json                   Print packet, alert, stats, and completion events as JSON lines
  --count <n>              Stop after n packets
  --no-packet-log          Disable packet event logging
  --no-alert-log           Disable alert logging
  --verbose                Print detailed packet output
  --quiet                  Print only alerts and important messages
  --disable-suspicious-port  Disable the Suspicious Port rule
  --disable-syn-watch      Disable the TCP SYN Watch rule
  --disable-icmp-echo      Disable the ICMP Echo Request rule
  --disable-port-scan      Disable port scan detection
  --disable-syn-flood      Disable SYN flood detection
  --disable-icmp-flood     Disable ICMP flood detection
```

## Logs And Stats

Packet events are saved to `logs/giftids.log` by default. Alerts are saved to
`logs/giftids_alerts.log` by default. Both paths can be changed in config or
overridden on the CLI. Alert log entries include severity, type, source,
destination, protocol, counters, evidence, and recommendation fields.

`--stats` prints live statistics during live capture, and Gift IDS prints a
final summary when capture or PCAP analysis finishes:

```text
================ Gift IDS Final Summary ================
Runtime: 00:00:01
Packets captured: 12
Valid packets: 11
Invalid packets: 1
TCP packets: 8
UDP packets: 2
ICMP packets: 1
Other packets: 0
Bytes seen: 4.8 KB
Total alerts: 3
Low alerts: 1
Medium alerts: 2
High alerts: 0
========================================================
```

When `--json --stats` is enabled, live and final stats are emitted as JSON
events instead of human text so the output remains parseable as JSON lines.

## Safety And Privacy

Gift IDS may capture sensitive network metadata such as IP addresses, ports, and
traffic patterns. Only run it on networks you own or have permission to monitor.
Do not publish logs or reports from private networks without removing sensitive
information.

Only use PCAP files from your own lab or trusted sources; packet captures can
contain private traffic.
