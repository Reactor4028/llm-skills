---
type: reference
title: Wireshark and tshark requests translated to tcpdump
---

# Wireshark and tshark requests translated to tcpdump

Load when the user mentions Wireshark, tshark or a Wireshark-style task (display filter, follow stream, conversations, expert info). Do not run or suggest Wireshark, tshark, mergecap or editcap; they may be unavailable or not permitted. Translate the request, run the tcpdump equivalent, and state any gap from the table below in one sentence.

[Translation table](#translation-table) | [Recipes](#recipes) | [What tcpdump cannot replace](#what-tcpdump-cannot-replace)

## Translation table

| Wireshark/tshark request | tcpdump approach | Gap to state |
|---|---|---|
| Open or read a capture (`tshark -r`) | `<build> -r FILE -nn` | None |
| Capture filter (`-f`) | Same BPF syntax as the expression | None |
| Display filter (`-Y 'ip.addr==X && tcp.port==443'`) | BPF on read: `-r FILE 'host X and tcp port 443'` | BPF knows addresses, ports and protocols, not decoded fields such as `http.host` or `tls.handshake` |
| Field filter on decoded text | Print with `-nn` (add `-v` for more), then filter lines with `grep`/`rg` | Text matching, not protocol-aware |
| Save a filtered subset (`-w` with `-Y`) | `-r IN -w OUT 'filter'` | Only BPF filters |
| Follow TCP stream | `-r FILE -A 'tcp and host X and port P'` (or `-X` for hex) | No reassembly or reordering; readable only for cleartext |
| Conversations / endpoints (`-z conv,tcp`, `-z endpoints,ip`) | Count `src > dst` pairs from text output ([recipe](#conversations-and-endpoints)) | No byte totals or durations per conversation |
| Protocol hierarchy (`-z io,phs`) | Count by protocol with separate BPF passes: `tcp`, `udp`, `icmp`, `ip6` and `--count` | No layered breakdown |
| I/O graph or traffic over time (`-z io,stat`) | Bucket `-tttt` timestamps per second or minute ([recipe](#traffic-over-time)) | No graph; text counts only |
| Expert info: resets, SYN retries | Match TCP flags in text output ([recipe](#tcp-problems)) | Heuristic only |
| Expert info: retransmissions | Repeated sequence ranges with `-S` ([recipe](#tcp-problems)) | Heuristic; misses retransmissions with different segment boundaries |
| Field export (`-T fields -e`) | Parse `-nn -tttt` text with `awk` | Field positions vary by protocol and build |
| Decode-as / app-protocol dissectors | tcpdump decodes many protocols; others print as raw payload (`-X`) | Fewer dissectors; no custom port mappings |
| Time display / relative time | `-tttt` (date and time), `-ttttt` (delta since first packet) | None |
| Split a file (`editcap -c`) | `-r IN -w OUT -C MB` (size-based) | Size only, not packet count |
| Merge files (`mergecap`) | Not available. Read each file in turn | Cannot produce one merged file |
| Process name per packet (macOS) | Apple `-k NPID` on pktap/pcapng captures ([builds](builds.md)) | tcpdump is better here: Wireshark does not show macOS process metadata by default |

## Recipes

These run in bash or zsh. Set `capture_path` to the file and use the build that wrote it (Apple for pktap/pcapng with metadata). Keep `-r` first.

### Conversations and endpoints

```bash
capture_path='/path/to/capture.pcapng'
/usr/sbin/tcpdump -r "$capture_path" -nn -q 2>/dev/null \
  | grep -oE 'IP6? [^ ]+ > [^ ]+:' | sed 's/:$//' \
  | sort | uniq -c | sort -rn | head -20
```

Each line is a packet count for one direction (`source.port > destination.port`). Reverse directions appear as separate lines. For endpoints only, drop the ports: add `| sed -E 's/\.[0-9]+( |$)/\1/g'` before `sort`.

### Traffic over time

```bash
/usr/sbin/tcpdump -r "$capture_path" -nn -tttt -q 2>/dev/null \
  | cut -c1-19 | sort | uniq -c
```

Counts packets per second. Use `cut -c1-16` for per-minute buckets.

### TCP problems

```bash
# Resets and SYNs (repeated SYNs to the same destination suggest connection retries)
/usr/sbin/tcpdump -r "$capture_path" -nn 'tcp' 2>/dev/null | grep -E 'Flags \[(R|S)\.?\]' | head -40

# Possible retransmissions: the same direction and sequence range seen more than once
/usr/sbin/tcpdump -r "$capture_path" -nn -S 'tcp' 2>/dev/null \
  | grep -oE 'IP6? [^ ]+ > [^ ]+: Flags \[[^]]*\], seq [0-9]+:[0-9]+' \
  | sort | uniq -d -c | sort -rn | head -20
```

Match flags by text, not with `tcp[tcpflags]`: transport-header arithmetic applies only to IPv4 packets. Duplicate sequence ranges can also come from capturing one packet on two interfaces with `pktap,all`; check the interface with `-k I` before calling it a retransmission.

## What tcpdump cannot replace

State the relevant gap plainly instead of approximating silently:

- **TLS decryption** (key log files): not available. Encrypted payloads stay unreadable.
- **Stream reassembly and file extraction** (export objects): not available.
- **Graphical views**: flow graphs, I/O graphs, packet coloring.
- **Protocol-aware display filters** on decoded fields.
- **Automatic expert analysis**: the recipes above are heuristics.

If a gap blocks the user's goal, say so and ask whether an approximation is enough. Do not suggest installing or using Wireshark or tshark.
