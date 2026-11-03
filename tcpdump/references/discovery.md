---
type: reference
title: discover.py options, JSON fields and limits
---

# discover.py options, JSON fields and limits

Load when choosing discovery options, reading the discovery JSON, or handling a discovery error. Applies to `scripts/discover.py` schema 2.0. Use the fields to choose build, interface, filter and capture options: [capture](capture.md).

[Run](#run) | [Options](#options) | [Fields](#fields) | [Notes](#notes) | [Reading the JSON](#reading-the-json) | [Limits](#limits) | [Exit codes and errors](#exit-codes-and-errors)

## Run

Command: `SKILL.md` workflow step 2. Runs in bash or zsh from the skill root.

With `--output`, stdout is one summary line, e.g. `{"output": "...", "bytes": 1432, "errors": 0}`. The file is created owner-only (0600) and must be outside the skill folder.

## Options

| Option | Use |
|---|---|
| `--target HOST` | IP or hostname to resolve and route. Repeat up to 16. Hostnames, not URLs |
| `--process "NAME"` | Case-insensitive substring of an app or process name the user gave. Includes matching apps even without open sockets, and system processes |
| `--network-apps` | List user apps with open TCP/UDP sockets, helpers grouped under their app. Use when the user has not named an app |
| `--include-system` | With `--network-apps`, also list Apple system processes |
| `--all-interfaces` | Include interfaces and capture devices without usable addresses. Only for debugging |
| `--capture-dir DIR` | Folder to check for writability and free space. Default: home folder |
| `--output FILE` | Write JSON to FILE instead of stdout |

Rerun discovery after a VPN or network change, an app restart (PIDs change), or new targets.

## Fields

Absent fields mean "nothing to report", not "unknown". `errors` appears only when a command failed.

| Field | Contents | Decision it drives |
|---|---|---|
| `executables.apple` / `.homebrew` | `path`, `version` (first line of `--version`), or `null` if absent | Which build and full path to use |
| `executables.bare_tcpdump_resolves_to` | What a bare `tcpdump` would run | Why full paths are required |
| `capture_devices` | `tcpdump -D` names, disconnected devices dropped | `-i` value must be in this list (`pktap,all` is always accepted by Apple) |
| `interfaces[]` | `name`, `tunnel` (true for point-to-point or tunnel-named), `ipv4`, `ipv6` (non-loopback, non-link-local), `status` | Candidate capture interfaces. Only interfaces with a usable address are listed |
| `default_routes.ipv4` / `.ipv6` | `interface`, `gateway` | Default path per address family |
| `dns_resolvers[]` | `scope` (`default` or `scoped`), `domains`, `interface` (scoped only), `nameservers[]` with `address`, `interface`, `gateway` | Which interface DNS queries would use; include port 53 on that interface when DNS matters |
| `proxy` | Enabled settings only: `http`, `https`, `socks` (`host:port`), `pac_url`, `auto_discovery` | Filter on the proxy address, not the target |
| `targets[]` | `target`, `addresses[]` with `address`, `interface`, `gateway`; `family_split`; `error`; `addresses_omitted` | Interface and BPF `host` addresses per destination |
| `notes[]` | Decision hints; see [Notes](#notes) | Interface choice |
| `network_apps.apps[]` | `app`, `pids`, `process_names`, `tcp`, `udp`, `remotes` (up to 5 remote IPs), `system`, `*_omitted` counts | Ask the user to pick an app; `process_names` and `pids` feed `--apple-md-filter` |
| `network_apps.apps_omitted` | Apps beyond the first 25 | Use `--process` to target one |
| `capture_dir` | `path`, `writable`, `free_gib`, `used_pct`, or `error` | Whether to use `-C`/`-W` rotation or a smaller `-s` |
| `errors[]` | `argv`, `returncode` (`null` if the command could not start or timed out), `error` | A failed check; do not treat its missing data as a negative result |

Apps are grouped by the outermost `.app` bundle in the executable path, so browser and Electron helpers merge under their app. `app` is the bundle name; the name to use in a metadata filter is in `process_names`. Apps are sorted by socket count. `system` marks executables under `/System/`, `/usr/`, `/sbin/`, `/bin/` or `/Library/Apple/`; some Apple helpers live elsewhere and are not marked.

## Notes

| Note | Meaning | Action |
|---|---|---|
| `ipv4_via_tunnel_ipv6_direct` | IPv4 (default route, a nameserver or a target) uses a tunnel while IPv6 leaves on a non-tunnel interface | Capture with Apple `-i pktap,all`, not one tunnel interface |
| `target_family_split` | A target's IPv4 and IPv6 addresses route via different interfaces | Same as above, or capture both interfaces |
| `proxy_enabled` | A system proxy is configured | Filter on the proxy address |

## Reading the JSON

Read slices with `jq` rather than printing the whole file:

```bash
discovery="${TMPDIR:-$(getconf DARWIN_USER_TEMP_DIR)}/tcpdump-discovery.json"
jq -c '{exe: .executables, ifs: .interfaces, routes: .default_routes, notes, dir: .capture_dir, errors}' "$discovery"
jq -c '.network_apps.apps[] | {app, process_names, pids, tcp, udp}' "$discovery"
jq -c '.dns_resolvers[] | {scope, domains, nameservers}' "$discovery"
```

## Limits

- Read-only: no sudo, packet capture, HTTP probes or configuration changes.
- Hostname targets are resolved through the system resolver and may send DNS queries. Literal IPs are not resolved.
- Route results predict the path; they do not prove it. Packets captured on an interface do.
- `tunnel` means tunnel-like, not a confirmed VPN or a known VPN client.
- Socket lists are a snapshot; short-lived connections can be missed.
- Each command times out after 8 seconds, without retries. Caps: 16 targets, 16 addresses per target, 16 nameserver routes, 25 apps, 16 PIDs, 8 process names and 5 remotes per app. Anything cut is reported in an `*_omitted` field.

## Exit codes and errors

| Code | Meaning | Action |
|---|---|---|
| 0 | Completed | Check `errors` for failed commands |
| 2 | Invalid arguments, not macOS, or Python older than 3.12 (JSON `error` names the interpreter found) | Fix the arguments, or report the Python requirement to the user. Do not switch interpreters yourself |
| 3 | Output file could not be written | Choose another path outside the skill folder |
