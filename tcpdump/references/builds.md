---
type: reference
title: Apple versus Homebrew tcpdump builds
---

# Apple versus Homebrew tcpdump builds

Load when choosing options that differ by build, using Apple process metadata, or looking up an option in the installed manual. Verified against Apple 4.99.1 (Apple version 158) and Homebrew 4.99.7 manuals; if `--version` is newer, recheck in the installed manual.

[Differences](#differences) | [Apple metadata display](#apple-metadata-display) | [Apple metadata filter](#apple-metadata-filter) | [Multi-interface capture](#multi-interface-capture) | [Manual lookup](#manual-lookup)

## Differences

| Feature | Apple `/usr/sbin/tcpdump` | Homebrew `.../opt/tcpdump/bin/tcpdump` |
|---|---|---|
| Print packet metadata | `-k [flags]` / `--apple-md-print` | Not available |
| Filter on metadata (process, PID, interface, direction) | `--apple-md-filter EXPR` (also `-Q EXPR`) | Not available |
| `-Q` | Direction (`in`, `out`, `inout`) or a metadata expression | Direction only |
| Force pcapng when saving | `-P` / `--apple-pcapng` | Not available |
| All interfaces incl. tunnel and loopback | `-i pktap,all` (or `-i all`) | Manual documents `-i any` on recent macOS; confirm it appears in `-D` first |
| Verbose output on one line | `-g` / `--apple-oneline` | `-g` / `--ip-oneline` |
| `--count` (reading files) | Prints the count on **stderr** | Prints the count on **stdout** |
| Default snapshot length (`-s 0`) | 262144 bytes | 262144 bytes |

When redirecting `--count` output, capture both streams (`2>&1`) so the command works with either build.

## Apple metadata display

`-k` alone prints all available metadata. `-k` with a flag word prints selected fields:

| Flag | Field | Flag | Field |
|---|---|---|---|
| `I` | Interface | `C` | Comment |
| `N` | Process name | `F` | Flags |
| `P` | Process ID | `d` | Data link type |
| `S` | Service class | `f` | Flow identifier |
| `D` | Direction | `t` | Trace tag |
| `U` | Process UUID (off by default) | `V` | Verbose pcapng blocks (off by default) |
| `A` | All metadata | | |

Use `-k NPID` for process name, PID, interface and direction. The `N` flag inside `-k` is unrelated to the top-level `-N` option.

Metadata exists only on a pktap capture or a pcapng file that kept it. A legacy pcap file has none.

## Apple metadata filter

Keywords: `if`, `proc`, `pid`, `eproc` (effective process name), `epid` (effective PID), `svc`, `dir`, `dlt`.
Operators: `=`, `!=`, `and`, `or`, `not`, `&&`, `||`, `!`, parentheses.

```zsh
--apple-md-filter "proc = 'App Name' or eproc = 'App Name'"
--apple-md-filter "pid = 12345 or epid = 12345"
--apple-md-filter "if = utun"
```

- Quote the whole expression; quote names that contain spaces inside it.
- Interface names match by prefix when the unit number is omitted (`if = en` matches en0, en1 and so on). Process names do not; use the exact name from discovery.
- `eproc`/`epid` match traffic a system process sends on an app's behalf, when macOS recorded that attribution. They cannot recover packets that carry no attribution.
- Prefer `--apple-md-filter` over `-Q` so the intent is clear.

## Multi-interface capture

- With no `-i`, Apple tcpdump captures on a kernel-chosen set of interfaces that **excludes loopback and tunnel interfaces**.
- `-i pktap,all` captures every interface, including tunnels and loopback, and writes pcapng with metadata by default.
- `-i pktap,lo0,en0` captures a chosen list.
- Captures on pktap are not promiscuous. Forcing `-y RAW` drops the metadata and writes legacy pcap.

## Manual lookup

The manual source escapes hyphens (`\-\-apple\-md\-filter`), so a plain search of the raw file misses options. Search the rendered text instead:

```zsh
MANPAGER=cat man /usr/share/man/man1/tcpdump.1 | col -b | rg -n -F -e '--apple-md-filter'
MANPAGER=cat man /opt/homebrew/opt/tcpdump/share/man/man1/tcpdump.1 | col -b | rg -n -F -e '--count'
```

- Then read a bounded range around the match (pipe through `sed -n 'START,ENDp'`) instead of the whole page.
- Use these explicit paths. A plain `man tcpdump` shows whichever page comes first in the manual search path, which may not match the build you are running.
- On Intel Macs the Homebrew page is under `/usr/local/opt/tcpdump/share/man/man1/`.
