---
type: reference
title: Building tcpdump commands and the sudo handoff
---

# Building tcpdump commands and the sudo handoff

Load before giving the user any live-capture command, or when choosing filters and capture options. Build choice and option differences: [builds](builds.md).

[Handoff](#handoff) | [Inputs from discovery](#inputs-from-discovery) | [Templates](#templates) | [Filters](#filters) | [Options](#options) | [After the capture](#after-the-capture)

## Handoff

Live capture needs sudo, so the user runs it. Never run a sudo or live-capture command yourself, even if a shell tool is available; a non-interactive session cannot press Control-C.

1. Say which build, interface and filter you chose and why, in one or two sentences.
2. Give one complete, paste-ready zsh block. Fill every value from discovery or the user; never hand over unfilled placeholders.
3. Tell the user to: start it, reproduce the action once, press Control-C once, then paste the full terminal output (including errors and the final packet counters).
4. Do not claim the capture ran or the file exists until the pasted output shows it.
5. If sudo is denied, stop. Do not retry, suggest workarounds, or ask for a password.

Pasted blocks run in the user's current shell: no `exit` (it closes the shell) and no background jobs (`&`).

## Inputs from discovery

| Value | Discovery field | Use |
|---|---|---|
| Build path | `executables.apple.path` / `executables.homebrew.path` | Full path in every command |
| Interface | `interfaces`, `capture_devices`, `default_routes`, `targets[].addresses[].interface` | `-i` value; must appear in `capture_devices` (except `pktap,all`) |
| App name | `network_apps.apps[].process_names` | `proc =` / `eproc =` value; use the exact name, not the bundle name, when they differ |
| PIDs | `network_apps.apps[].pids` | `pid =` / `epid =`; only from the current discovery run |
| Destination | `targets[].addresses[].address`, or `proxy` when present | BPF `host` filter |
| Output folder | `capture_dir.path`, `writable`, `free_gib` | Free space for `-w`; see [Options](#options) for low space |

Use `-i pktap,all` (Apple) when discovery shows the `ipv4_via_tunnel_ipv6_direct` note, when the target routes through a tunnel, or when you are unsure which interface the traffic uses.

## Templates

Replace the example values with real ones before presenting. Captures go to the macOS per-user temp folder from `getconf DARWIN_USER_TEMP_DIR`, never `$TMPDIR`: agent harnesses may set their own `$TMPDIR` that differs from the user's terminal. The block creates an owner-only subfolder, checks the output path, and prints the full capture path before starting. Read the file from that printed path.

Temp captures may be removed by macOS cleanup after a few days. Tell the user to move a capture they want to keep, or use a folder they name.

**App traffic on all interfaces, with process metadata (Apple):**

```zsh
capture_dir="$(getconf DARWIN_USER_TEMP_DIR)"
capture_dir="${capture_dir%/}/tcpdump-captures"
capture_path="$capture_dir/app-$(date +%Y%m%dT%H%M%S).pcapng"
mkdir -p -m 700 "$capture_dir"
if [[ ! -w "$capture_dir" ]]; then
  print -r -- "HALT: $capture_dir is not writable"
elif [[ -e "$capture_path" ]]; then
  print -r -- "HALT: $capture_path already exists"
else
  print -r -- "Capture file: $capture_path"
  sudo /usr/sbin/tcpdump -i pktap,all -nn -U -Z "$(id -un)" \
    --apple-md-filter "proc = 'App Name' or eproc = 'App Name'" \
    -w "$capture_path"
fi
```

**Specific host on one interface:** use the same block with the chosen build, `-i` from discovery, a `.pcap` name, and a BPF filter instead of `--apple-md-filter`, e.g. `-i en0 ... -w "$capture_path" 'host 203.0.113.10'`.

This block runs in the user's terminal (zsh). pktap captures are written as pcapng; single-interface captures are pcap.

## Filters

- BPF (the expression at the end) filters packet contents: hosts, ports, protocols. Both builds share it. Details: `man pcap-filter`.
- `--apple-md-filter` filters macOS metadata: process, PID, interface, direction. Apple only. Both kinds can be combined in one command.
- Filter on IP addresses from discovery, not hostnames. A hostname in BPF is resolved once at start, to whatever the resolver returns then.
- Include DNS when the question involves name resolution: `host 203.0.113.10 or port 53`. A `port 443` filter misses DNS (53), HTTP (80) and anything on other ports; QUIC uses UDP 443.
- Never let a filter silently become empty or broader. If a PID or name is missing, ask; do not drop the filter.

## Options

| Option | Use |
|---|---|
| `-nn` | No name or port lookups; faster and avoids extra DNS traffic |
| `-U` | Write each packet immediately, so Control-C loses nothing |
| `-Z "$(id -un)"` | Drop root after opening the device. Output files are then created as the user, so the user (and the agent) can read them without sudo |
| `-s N` | Shorter snapshot (e.g. `-s 128`) when only headers are needed; reduces size and payload exposure |
| `-c N` | Stop after N packets. Not a time limit; a quiet capture may never reach N |
| `-C MB -W N` | Ring buffer: rotate at MB (millions of bytes), keep N files, overwrite the oldest. Use when `capture_dir.free_gib` is low or the capture may run long |

## After the capture

From the user's pasted output, check first: the listening line (right interface?), packets captured, packets dropped by kernel, and any error. Zero captured packets: investigate per [interpretation](interpretation.md#empty-or-small-capture).

Then read the file yourself (no sudo needed), with the build that wrote it, using the path printed as `Capture file:`. These commands must work in bash: put `-r FILE` first so they match the skill's pre-approved commands, and do not use zsh-only syntax such as `print -r`.

```bash
capture_path='/var/folders/xx/example/T/tcpdump-captures/app-20260101T120000.pcapng'
ls -l "$capture_path"
/usr/sbin/tcpdump -r "$capture_path" -nn -tttt -k NPID -c 30
/usr/sbin/tcpdump -r "$capture_path" --count 2>&1
```

Drop `-k NPID` when reading with Homebrew or when the file is legacy pcap. Keep `2>&1` on `--count`; the builds print it to different streams. Interpretation: [interpretation](interpretation.md).
