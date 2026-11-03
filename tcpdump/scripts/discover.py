#!/usr/bin/env python3
"""---
type: script
title: Read-only macOS tcpdump discovery
description: Report only the facts that change tcpdump build, interface, filter and capture-option choices, as compact JSON.
tags: [tcpdump, macos, discovery]
status: draft
generated: 2026-11-02T16:39:57-08:00
verified: false
okf_version: "0.2"
sources:
  - id: discovery-reference
    resource: references/discovery.md
    title: Discovery fields, limits and refresh policy
---

Quick how to run (from the skill root; no sudo, no installs):
  python3 scripts/discover.py --help
  python3 scripts/discover.py --network-apps --output "${TMPDIR:-$(getconf DARWIN_USER_TEMP_DIR)}/tcpdump-discovery.json"
  python3 scripts/discover.py --target example.com --process "App Name"

Runtime: python3 must be 3.12+. Apple /usr/bin/python3 (3.9) is refused with exit 2.
Exit codes: 0 completed (inspect "errors"), 2 invalid arguments or unsupported
OS/Python, 3 output file could not be written.
"""

# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SCHEMA_VERSION = "2.0"
MIN_PYTHON = (3, 12)
COMMAND_TIMEOUT_SECONDS = 8
MAX_TARGETS = 16
MAX_ADDRESSES_PER_TARGET = 16
MAX_NAMESERVER_ROUTES = 16
MAX_APPS = 25
MAX_PIDS_PER_APP = 16
MAX_PROCESS_NAMES_PER_APP = 8
MAX_REMOTES_PER_APP = 5

APPLE_TCPDUMP = "/usr/sbin/tcpdump"
HOMEBREW_TCPDUMP_CANDIDATES = (
    "/opt/homebrew/opt/tcpdump/bin/tcpdump",  # Apple Silicon default prefix
    "/usr/local/opt/tcpdump/bin/tcpdump",  # Intel default prefix
)
TUNNEL_NAME_PREFIXES = ("utun", "ipsec", "ppp", "tun", "tap", "gif", "stf")
SYSTEM_PATH_PREFIXES = (
    "/System/",
    "/usr/",
    "/sbin/",
    "/bin/",
    "/Library/Apple/",
)
UNCAPTURABLE_DEVICE_MARKERS = ("Disconnected", "Not associated", "none")
SKILL_ROOT = Path(__file__).resolve().parents[1]


class CommandLog:
    """Run fixed argv vectors and keep only failures for the JSON report."""

    def __init__(self) -> None:
        self.errors: list[dict[str, object]] = []

    def run(self, argv: list[str], ok_codes: tuple[int, ...] = (0,)) -> str | None:
        """Return stdout on success; record and return None on any failure."""
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
                env={**os.environ, "LC_ALL": "C", "PAGER": "cat"},
            )
        except (OSError, subprocess.TimeoutExpired) as command_error:
            self.errors.append(
                {"argv": argv, "returncode": None, "error": str(command_error)}
            )
            return None
        if result.returncode not in ok_codes:
            self.errors.append(
                {
                    "argv": argv,
                    "returncode": result.returncode,
                    "error": result.stderr.strip()[:300] or "command failed",
                }
            )
            return None
        return result.stdout


# ---------------------------------------------------------------- parsers


def usable_address(text: str) -> str | None:
    """Return a normalized address unless it is loopback or link-local."""
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if address.is_loopback or address.is_link_local:
        return None
    return str(address)


def is_tunnel(name: str, flags: list[str]) -> bool:
    """Tunnel-like by flag or name; this is not proof of VPN ownership."""
    return "POINTOPOINT" in flags or name.startswith(TUNNEL_NAME_PREFIXES)


def parse_interfaces(text: str) -> list[dict[str, object]]:
    """Parse `ifconfig -a` into name, flags, usable addresses and status."""
    found: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in text.splitlines():
        header = re.match(r"(\S+):\s+flags=\w+<([^>]*)>", line)
        if header:
            flags = [flag for flag in header[2].split(",") if flag]
            current = {
                "name": header[1],
                "flags": flags,
                "ipv4": [],
                "ipv6": [],
                "status": None,
            }
            found.append(current)
            continue
        if current is None:
            continue
        address_match = re.match(r"\s+(inet6?)\s+(\S+)", line)
        if address_match:
            address = usable_address(address_match[2])
            if address is not None:
                family_key = "ipv6" if address_match[1] == "inet6" else "ipv4"
                family_list = current[family_key]
                if isinstance(family_list, list) and address not in family_list:
                    family_list.append(address)
            continue
        status_match = re.match(r"\s+status:\s+(\S+)", line)
        if status_match:
            current["status"] = status_match[1]
    return found


def compact_interfaces(
    parsed: list[dict[str, object]], include_all: bool
) -> list[dict[str, object]]:
    """Keep interfaces with a usable address unless --all-interfaces is set."""
    result: list[dict[str, object]] = []
    for interface in parsed:
        name = str(interface["name"])
        flags = interface["flags"] if isinstance(interface["flags"], list) else []
        has_address = bool(interface["ipv4"] or interface["ipv6"])
        if not include_all and not has_address:
            continue
        entry: dict[str, object] = {"name": name}
        if is_tunnel(name, flags):
            entry["tunnel"] = True
        if interface["ipv4"]:
            entry["ipv4"] = interface["ipv4"]
        if interface["ipv6"]:
            entry["ipv6"] = interface["ipv6"]
        if interface["status"]:
            entry["status"] = interface["status"]
        if include_all:
            entry["flags"] = flags
        result.append(entry)
    return result


def parse_route(text: str) -> dict[str, str]:
    """Keep the `route -n get` fields that choose a capture interface."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        key = key.strip()
        if separator and key in {"interface", "gateway"}:
            found[key] = value.strip()
    return found


def parse_resolvers(text: str) -> list[dict[str, object]]:
    """Parse `scutil --dns`; keys are padded, so strip before matching."""
    found: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    scope = "default"
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("DNS configuration"):
            scope = "scoped" if "scoped" in line else "default"
            current = None
            continue
        if re.fullmatch(r"resolver #\d+", line):
            current = {"scope": scope, "nameservers": [], "domains": []}
            found.append(current)
            continue
        if current is None:
            continue
        key, separator, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not separator or not value:
            continue
        if key.startswith("nameserver["):
            nameservers = current["nameservers"]
            if isinstance(nameservers, list) and value not in nameservers:
                nameservers.append(value)
        elif key == "domain" or key.startswith("search domain["):
            domains = current["domains"]
            if isinstance(domains, list) and value not in domains:
                domains.append(value)
        elif key == "if_index":
            interface_match = re.search(r"\((\S+)\)", value)
            if interface_match:
                current["interface"] = interface_match[1]
    return [resolver for resolver in found if resolver["nameservers"]]


def parse_resolution(text: str) -> list[str]:
    """Read `dscacheutil -q host` address fields, deduplicated in order."""
    found: list[str] = []
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in {"ip_address", "ipv6_address"}:
            try:
                address = str(ipaddress.ip_address(value.strip()))
            except ValueError:
                continue
            if address not in found:
                found.append(address)
    return found


def parse_proxy(text: str) -> dict[str, object]:
    """Return only enabled proxy settings from `scutil --proxy`."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.strip().partition(" : ")
        if separator:
            values[key.strip()] = value.strip()
    enabled: dict[str, object] = {}
    for kind in ("HTTP", "HTTPS", "SOCKS"):
        if values.get(f"{kind}Enable") == "1" and values.get(f"{kind}Proxy"):
            enabled[kind.lower()] = (
                f"{values[f'{kind}Proxy']}:{values.get(f'{kind}Port', '')}".rstrip(":")
            )
    if values.get("ProxyAutoConfigEnable") == "1":
        enabled["pac_url"] = values.get("ProxyAutoConfigURLString", "")
    if values.get("ProxyAutoDiscoveryEnable") == "1":
        enabled["auto_discovery"] = True
    return enabled


def parse_capture_devices(text: str, include_all: bool) -> list[str]:
    """Parse `tcpdump -D`; drop disconnected devices unless asked."""
    devices: list[str] = []
    for line in text.splitlines():
        device_match = re.match(r"\d+\.(\S+)(?:\s+\[(.*)\])?", line.strip())
        if not device_match:
            continue
        name, description = device_match[1], device_match[2] or ""
        if not include_all and any(
            marker in description for marker in UNCAPTURABLE_DEVICE_MARKERS
        ):
            continue
        devices.append(name)
    return devices


def parse_ps(text: str) -> dict[int, str]:
    """Map PID to executable path from `ps -axo pid=,comm=`."""
    table: dict[int, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            table[int(parts[0])] = parts[1]
    return table


def remote_address(name: str) -> str | None:
    """Extract the remote IP from an lsof `n` field such as a:1->b:443."""
    if "->" not in name:
        return None
    remote = name.split("->", 1)[1].split(" ", 1)[0]
    host = (
        remote[1:].split("]", 1)[0]
        if remote.startswith("[")
        else remote.rsplit(":", 1)[0]
    )
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    return None if address.is_loopback else str(address)


def parse_lsof(text: str) -> dict[int, dict[str, object]]:
    """Parse `lsof -F pcfPn` into per-PID command name and socket counts."""
    sockets: dict[int, dict[str, object]] = {}
    current: dict[str, object] | None = None
    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p" and value.isdigit():
            current = {"command": "", "tcp": 0, "udp": 0, "remotes": []}
            sockets[int(value)] = current
        elif current is None:
            continue
        elif tag == "c":
            current["command"] = value
        elif tag == "P":
            protocol_key = value.lower()
            if protocol_key in {"tcp", "udp"}:
                count = current[protocol_key]
                current[protocol_key] = (count if isinstance(count, int) else 0) + 1
        elif tag == "n":
            remote = remote_address(value)
            remotes = current["remotes"]
            if remote and isinstance(remotes, list) and remote not in remotes:
                remotes.append(remote)
    return sockets


def app_identity(executable: str) -> tuple[str, bool]:
    """Group by outermost .app bundle; flag Apple system paths."""
    bundle_match = re.match(r"(.*?/([^/]+)\.app)(?:/|$)", executable)
    system = executable.startswith(SYSTEM_PATH_PREFIXES)
    if bundle_match:
        return str(bundle_match[2]), system
    return Path(executable).name or executable, system


def group_apps(
    process_table: dict[int, str],
    sockets: dict[int, dict[str, object]],
    needle: str | None,
    include_system: bool,
) -> dict[str, object]:
    """Merge helper processes under their app; filter by --process if given."""
    groups: dict[str, dict[str, object]] = {}
    pids = set(sockets) | (set(process_table) if needle else set())
    for pid in sorted(pids):
        socket_info = sockets.get(pid, {})
        command = str(socket_info.get("command", ""))
        executable = process_table.get(pid) or command
        if not executable:
            continue
        app_name, system = app_identity(executable)
        process_name = command or Path(executable).name
        if needle:
            folded = needle.casefold()
            if (
                folded not in executable.casefold()
                and folded not in process_name.casefold()
            ):
                continue
        elif system and not include_system:
            continue
        group = groups.setdefault(
            app_name,
            {
                "app": app_name,
                "pids": [],
                "process_names": [],
                "tcp": 0,
                "udp": 0,
                "remotes": [],
            },
        )
        group_pids = group["pids"]
        names = group["process_names"]
        remotes = group["remotes"]
        if isinstance(group_pids, list):
            group_pids.append(pid)
        if isinstance(names, list) and process_name not in names:
            names.append(process_name)
        for protocol_key in ("tcp", "udp"):
            count = socket_info.get(protocol_key, 0)
            total = group[protocol_key]
            group[protocol_key] = (total if isinstance(total, int) else 0) + (
                count if isinstance(count, int) else 0
            )
        socket_remotes = socket_info.get("remotes", [])
        if isinstance(remotes, list) and isinstance(socket_remotes, list):
            remotes.extend(item for item in socket_remotes if item not in remotes)
        if system:
            group["system"] = True

    def socket_total(group: dict[str, object]) -> int:
        tcp_count, udp_count = group["tcp"], group["udp"]
        return (tcp_count if isinstance(tcp_count, int) else 0) + (
            udp_count if isinstance(udp_count, int) else 0
        )

    ordered = sorted(
        groups.values(), key=lambda group: (-socket_total(group), str(group["app"]))
    )
    for group in ordered:
        for key, limit in (
            ("pids", MAX_PIDS_PER_APP),
            ("process_names", MAX_PROCESS_NAMES_PER_APP),
            ("remotes", MAX_REMOTES_PER_APP),
        ):
            values = group[key]
            if isinstance(values, list) and len(values) > limit:
                group[f"{key}_omitted"] = len(values) - limit
                group[key] = values[:limit]
        if not group["remotes"]:
            del group["remotes"]
    report: dict[str, object] = {"apps": ordered[:MAX_APPS]}
    if len(ordered) > MAX_APPS:
        report["apps_omitted"] = len(ordered) - MAX_APPS
    return report


# ---------------------------------------------------------------- discovery


def version_line(log: CommandLog, binary: str) -> str | None:
    """First line of `--version` (e.g. tcpdump version 4.99.1 -- Apple version 158)."""
    output = log.run([binary, "--version"])
    return output.splitlines()[0].strip() if output and output.strip() else None


def find_homebrew_tcpdump(log: CommandLog) -> str | None:
    """Prefer literal opt paths; use `brew --prefix` only as a fallback."""
    for candidate in HOMEBREW_TCPDUMP_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return candidate
    brew = shutil.which("brew")
    if not brew:
        return None
    prefix = log.run([brew, "--prefix", "tcpdump"])
    if not prefix:
        return None
    candidate = str(Path(prefix.strip()) / "bin" / "tcpdump")
    return candidate if os.access(candidate, os.X_OK) else None


def discover_executables(log: CommandLog) -> dict[str, object]:
    """Report both builds and which one a bare `tcpdump` would run."""
    executables: dict[str, object] = {
        "bare_tcpdump_resolves_to": shutil.which("tcpdump")
    }
    if os.access(APPLE_TCPDUMP, os.X_OK):
        executables["apple"] = {
            "path": APPLE_TCPDUMP,
            "version": version_line(log, APPLE_TCPDUMP),
        }
    else:
        executables["apple"] = None
    homebrew_path = find_homebrew_tcpdump(log)
    executables["homebrew"] = (
        {"path": homebrew_path, "version": version_line(log, homebrew_path)}
        if homebrew_path
        else None
    )
    return executables


class RouteCache:
    """Route each address once per invocation; returns interface/gateway."""

    def __init__(self, log: CommandLog) -> None:
        self.log = log
        self.cache: dict[str, dict[str, str]] = {}

    def lookup(self, destination: str, family: str) -> dict[str, str]:
        cache_key = f"{family}:{destination}"
        if cache_key not in self.cache:
            output = self.log.run(
                ["/sbin/route", "-n", "get", f"-{family}", destination]
            )
            self.cache[cache_key] = parse_route(output) if output else {}
        return self.cache[cache_key]

    def for_address(self, address: str) -> dict[str, str]:
        family = "inet6" if ":" in address else "inet"
        return self.lookup(address, family)


def resolve_target(log: CommandLog, target: str) -> tuple[list[str], str | None]:
    """Literal IPs pass through; hostnames use the system resolver cache."""
    try:
        return [str(ipaddress.ip_address(target.split("%", 1)[0]))], None
    except ValueError:
        pass
    output = log.run(["/usr/bin/dscacheutil", "-q", "host", "-a", "name", target])
    if output is None:
        return [], "resolution command failed"
    addresses = parse_resolution(output)
    return addresses, None if addresses else "no address records returned"


def discover_targets(
    log: CommandLog, routes: RouteCache, targets: list[str]
) -> list[dict[str, object]]:
    """Resolve and route each target; flag IPv4/IPv6 interface splits."""
    results: list[dict[str, object]] = []
    for target in targets:
        addresses, error = resolve_target(log, target)
        entry: dict[str, object] = {"target": target}
        if error:
            entry["error"] = error
        routed: list[dict[str, object]] = []
        for address in addresses[:MAX_ADDRESSES_PER_TARGET]:
            route = routes.for_address(address)
            routed.append({"address": address, **route})
        if len(addresses) > MAX_ADDRESSES_PER_TARGET:
            entry["addresses_omitted"] = len(addresses) - MAX_ADDRESSES_PER_TARGET
        if routed:
            entry["addresses"] = routed
            v4_interfaces = {
                item.get("interface")
                for item in routed
                if ":" not in str(item["address"])
            }
            v6_interfaces = {
                item.get("interface") for item in routed if ":" in str(item["address"])
            }
            if (
                v4_interfaces
                and v6_interfaces
                and v4_interfaces.isdisjoint(v6_interfaces)
            ):
                entry["family_split"] = True
        results.append(entry)
    return results


def tunnel_names(interfaces: list[dict[str, object]]) -> set[str]:
    return {
        str(interface["name"]) for interface in interfaces if interface.get("tunnel")
    }


def split_tunnel_notes(
    tunnels: set[str],
    default_routes: dict[str, dict[str, str]],
    nameserver_routes: dict[str, dict[str, str]],
    targets: list[dict[str, object]],
) -> list[str]:
    """Decision hints derived from route predictions, not observed packets."""
    v4_tunnel_seen = default_routes.get("ipv4", {}).get("interface") in tunnels
    v6_direct_seen = bool(default_routes.get("ipv6", {}).get("interface")) and (
        default_routes["ipv6"].get("interface") not in tunnels
    )
    for address, route in nameserver_routes.items():
        if ":" not in address and route.get("interface") in tunnels:
            v4_tunnel_seen = True
    for target in targets:
        routed = target.get("addresses")
        for item in routed if isinstance(routed, list) else []:
            if not isinstance(item, dict):
                continue
            interface = item.get("interface")
            if ":" not in str(item.get("address")) and interface in tunnels:
                v4_tunnel_seen = True
            if (
                ":" in str(item.get("address"))
                and interface
                and interface not in tunnels
            ):
                v6_direct_seen = True
    notes: list[str] = []
    if v4_tunnel_seen and v6_direct_seen:
        notes.append(
            "ipv4_via_tunnel_ipv6_direct: capture both families; use Apple -i pktap,all, not one tunnel interface"
        )
    if any(target.get("family_split") for target in targets):
        notes.append(
            "target_family_split: a target's IPv4 and IPv6 addresses route via different interfaces"
        )
    return notes


def discover_capture_dir(capture_dir: Path) -> dict[str, object]:
    """Writable check and free space for the intended capture directory."""
    entry: dict[str, object] = {"path": str(capture_dir)}
    if not capture_dir.is_dir():
        entry["error"] = "not a directory"
        return entry
    usage = shutil.disk_usage(capture_dir)
    entry["writable"] = os.access(capture_dir, os.W_OK)
    entry["free_gib"] = round(usage.free / 1024**3, 1)
    entry["used_pct"] = round(100 * usage.used / usage.total) if usage.total else None
    return entry


def discover(
    targets: list[str],
    process: str | None,
    network_apps: bool,
    include_system: bool,
    all_interfaces: bool,
    capture_dir: Path,
) -> dict[str, object]:
    """Collect once; every field maps to a tcpdump decision."""
    log = CommandLog()
    routes = RouteCache(log)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    executables = discover_executables(log)
    report["executables"] = executables

    device_binary = APPLE_TCPDUMP if executables.get("apple") else None
    homebrew = executables.get("homebrew")
    if device_binary is None and isinstance(homebrew, dict):
        device_binary = str(homebrew["path"])
    if device_binary:
        device_output = log.run([device_binary, "-D"])
        report["capture_devices"] = (
            parse_capture_devices(device_output, all_interfaces)
            if device_output
            else []
        )

    ifconfig_output = log.run(["/sbin/ifconfig", "-a"])
    interfaces = compact_interfaces(
        parse_interfaces(ifconfig_output) if ifconfig_output else [], all_interfaces
    )
    report["interfaces"] = interfaces

    default_routes = {
        "ipv4": routes.lookup("default", "inet"),
        "ipv6": routes.lookup("default", "inet6"),
    }
    report["default_routes"] = default_routes

    dns_output = log.run(["/usr/sbin/scutil", "--dns"])
    resolvers = parse_resolvers(dns_output) if dns_output else []
    nameserver_routes: dict[str, dict[str, str]] = {}
    for resolver in resolvers:
        nameservers = (
            resolver["nameservers"] if isinstance(resolver["nameservers"], list) else []
        )
        for nameserver in nameservers:
            address = str(nameserver)
            if (
                len(nameserver_routes) >= MAX_NAMESERVER_ROUTES
                or address in nameserver_routes
            ):
                continue
            route = (
                routes.for_address(address)
                if usable_address(address) or "%" in address
                else {}
            )
            nameserver_routes[address] = route
    for resolver in resolvers:
        if not resolver["domains"]:
            del resolver["domains"]
        nameservers = (
            resolver["nameservers"] if isinstance(resolver["nameservers"], list) else []
        )
        resolver["nameservers"] = [
            {"address": str(address), **nameserver_routes.get(str(address), {})}
            for address in nameservers
        ]
    report["dns_resolvers"] = resolvers

    proxy_output = log.run(["/usr/sbin/scutil", "--proxy"])
    proxy = parse_proxy(proxy_output) if proxy_output else {}
    if proxy:
        report["proxy"] = proxy

    target_results = discover_targets(log, routes, targets)
    if target_results:
        report["targets"] = target_results

    notes = split_tunnel_notes(
        tunnel_names(interfaces), default_routes, nameserver_routes, target_results
    )
    if proxy:
        notes.append(
            "proxy_enabled: app traffic may go to the proxy; filter on the proxy address"
        )
    if notes:
        report["notes"] = notes

    if network_apps or process:
        lsof_output = log.run(
            ["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "+c", "0", "-F", "pcfPn"],
            ok_codes=(0, 1),
        )
        ps_output = log.run(["/bin/ps", "-axo", "pid=,comm="])
        report["network_apps"] = group_apps(
            parse_ps(ps_output) if ps_output else {},
            parse_lsof(lsof_output) if lsof_output else {},
            process,
            include_system,
        )

    report["capture_dir"] = discover_capture_dir(capture_dir)
    if log.errors:
        report["errors"] = log.errors
    return report


# ---------------------------------------------------------------- CLI


def target_value(value: str) -> str:
    """Accept IP literals or ASCII hostnames; reject URLs, options, shell syntax."""
    if not value or len(value) > 253:
        raise argparse.ArgumentTypeError(
            "target must be a nonempty IP or hostname, <=253 characters"
        )
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        labels = value[:-1].split(".") if value.endswith(".") else value.split(".")
        label_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        if not all(re.fullmatch(label_pattern, label) for label in labels):
            raise argparse.ArgumentTypeError(
                f"use an IP or ASCII hostname, not a URL or expression: {value!r}"
            ) from None
    return value


def process_value(value: str) -> str:
    if not value.strip() or len(value) > 128:
        raise argparse.ArgumentTypeError(
            "--process must be nonempty and <=128 characters"
        )
    return value


def output_path(value: str) -> Path:
    """Refuse output inside the skill folder; results are session data."""
    path = Path(value).expanduser().resolve()
    if path == SKILL_ROOT or SKILL_ROOT in path.parents:
        raise argparse.ArgumentTypeError(
            "--output must be outside the skill folder (use the workspace or the per-user temp folder)"
        )
    if path.is_dir():
        raise argparse.ArgumentTypeError(f"--output is a directory: {path}")
    return path


def write_private(path: Path, text: str) -> None:
    """Create or replace the file with owner-only (0600) permissions."""
    file_descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(file_descriptor, 0o600)
        os.write(file_descriptor, text.encode("utf-8"))
    finally:
        os.close(file_descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discover.py",
        description=(
            "Read-only macOS discovery for tcpdump decisions. No sudo, no packet "
            "capture, no HTTP probes, no configuration changes. Hostname targets "
            "use the system resolver and may generate DNS traffic."
        ),
        epilog=(
            "Exit codes: 0 completed (inspect 'errors'), 2 invalid arguments or "
            "unsupported OS/Python, 3 output file not written."
        ),
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        type=target_value,
        help=f"IP or hostname to resolve and route; repeat up to {MAX_TARGETS} times",
    )
    parser.add_argument(
        "--process",
        type=process_value,
        help="case-insensitive substring of an app or process name supplied by the user",
    )
    parser.add_argument(
        "--network-apps",
        action="store_true",
        help="list user apps with open TCP/UDP sockets, helpers grouped under their app",
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="with --network-apps, include Apple system processes",
    )
    parser.add_argument(
        "--all-interfaces",
        action="store_true",
        help="include interfaces and capture devices without usable addresses",
    )
    parser.add_argument(
        "--capture-dir",
        type=Path,
        default=Path.home(),
        help="directory for the planned capture file (default: home); reports writable and free space",
    )
    parser.add_argument(
        "--output",
        type=output_path,
        help="write JSON to this file (mode 0600) and print only a short summary; never inside the skill folder",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if len(args.target) > MAX_TARGETS:
        parser.error(f"at most {MAX_TARGETS} --target values per invocation")
    if sys.version_info < MIN_PYTHON:
        found = ".".join(str(part) for part in sys.version_info[:3])
        print(
            json.dumps(
                {
                    "error": f"Python 3.12+ required; found {found} at {sys.executable}",
                    "hint": "use a newer python3 from PATH, e.g. Homebrew python3",
                }
            )
        )
        return 2
    if sys.platform != "darwin":
        print(json.dumps({"error": "macOS required; no discovery commands executed"}))
        return 2
    report = discover(
        args.target,
        args.process,
        args.network_apps,
        args.include_system,
        args.all_interfaces,
        args.capture_dir.expanduser(),
    )
    text = json.dumps(report, separators=(",", ":"))
    if args.output is None:
        print(text)
        return 0
    try:
        write_private(args.output, text + "\n")
    except OSError as write_error:
        print(json.dumps({"error": f"could not write {args.output}: {write_error}"}))
        return 3
    recorded_errors = report.get("errors")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "bytes": len(text) + 1,
                "errors": len(recorded_errors)
                if isinstance(recorded_errors, list)
                else 0,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
