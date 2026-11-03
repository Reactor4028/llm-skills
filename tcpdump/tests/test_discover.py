"""---
type: test
title: Unit tests for scripts/discover.py
description: Synthetic macOS-shaped fixtures and mocked commands that validate discover.py parsing, grouping, routing notes, CLI guards and output handling.
tags: [tcpdump, macos, discovery, pytest]
status: draft
generated: 2026-11-02T16:49:48-08:00
verified: false
okf_version: "0.2"
sources:
  - id: discover-script
    resource: scripts/discover.py
    title: Read-only macOS tcpdump discovery script under test
---

Quick how to run (from the skill root; maintainer only, never run by the agent):
  uv run --with pytest pytest -q tests

Scope: fixtures use documentation-reserved addresses (RFC 5737 / RFC 3849) and
mock every subprocess call. Passing tests prove parser and decision logic, not
real macOS command behavior, network paths or agent triggering.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "discover.py"
_module_spec = importlib.util.spec_from_file_location("discover", SCRIPT_PATH)
assert _module_spec is not None and _module_spec.loader is not None
discover = importlib.util.module_from_spec(_module_spec)
sys.modules["discover"] = discover
_module_spec.loader.exec_module(discover)

# ---------------------------------------------------------------- fixtures

IFCONFIG_OUTPUT = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
stf0: flags=0<> mtu 1280
en4: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tstatus: inactive
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1c59%en0 prefixlen 64 secured scopeid 0xe
\tinet6 2001:db8::844c prefixlen 64 autoconf secured
\tinet 192.0.2.83 netmask 0xffffff00 broadcast 192.0.2.255
\tstatus: active
awdl0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::5840%awdl0 prefixlen 64 scopeid 0xf
\tstatus: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet6 fe80::9bb0%utun0 prefixlen 64 scopeid 0x11
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.0.0.78 --> 10.0.0.78 netmask 0xffffffff
"""

# Keys are space-padded exactly as macOS prints them (the v1 parser bug).
SCUTIL_DNS_OUTPUT = """DNS configuration

resolver #1
  search domain[0] : corp.example
  search domain[1] : example
  nameserver[0] : 10.1.1.53
  nameserver[1] : 10.2.2.53
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : localdomain
  nameserver[0] : 2001:db8::1
  nameserver[1] : 192.0.2.1
  if_index : 14 (en0)
  flags    : Scoped, Request A records, Request AAAA records
"""

SCUTIL_PROXY_EMPTY = "<dictionary> {\n}\n"
SCUTIL_PROXY_ENABLED = """<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.example
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://pac.example/proxy.pac
}
"""

TCPDUMP_DEVICES_OUTPUT = """1.ap1 [Up, Running, Wireless, Not associated]
2.en0 [Up, Running, Wireless, Associated]
5.utun0 [Up, Running]
12.lo0 [Up, Running, Loopback]
16.en4 [Up, Running, Disconnected]
23.pktap0 [Up]
24.gif0 [none]
"""

# App names are deliberately generic; the script must not depend on browser names.
PS_OUTPUT = """  100 /Applications/Sample Browser.app/Contents/MacOS/Sample Browser
  101 /Applications/Sample Browser.app/Contents/Frameworks/Sample.framework/Versions/1/Helpers/Sample Browser Helper (Renderer).app/Contents/MacOS/Sample Browser Helper (Renderer)
  200 /System/Library/PrivateFrameworks/Example.framework/networkserviceproxy
  300 /opt/homebrew/bin/curl
"""

LSOF_OUTPUT = """p100
cSample Browser
f30
PTCP
n192.0.2.83:50000->203.0.113.10:443
f31
PUDP
n*:5353
p101
cSample Browser Helper (Renderer)
f12
PTCP
n[2001:db8::844c]:50001->[2001:db8:1::10]:443
f13
PTCP
n192.0.2.83:50002->127.0.0.1:9000
p200
cnetworkserviceproxy
f5
PTCP
n10.0.0.78:50003->198.51.100.5:443
p300
ccurl
f3
PTCP
n192.0.2.83:50004->203.0.113.10:443
"""

DSCACHEUTIL_OUTPUT = """name: app.example
ipv6_address: 2001:db8:1::10

name: app.example
ip_address: 203.0.113.10
ip_address: 203.0.113.10
ip_address: not-an-address
"""

TCPDUMP_VERSION_OUTPUT = (
    "tcpdump version 4.99.1 -- Apple version 158\nlibpcap version 1.10.1\n"
)


def route_output(destination: str, family_flag: str) -> str:
    """Synthetic `route -n get`: defaults and public hosts on en0, 10/8 on utun4."""
    if destination == "default":
        if family_flag == "-inet":
            return "  gateway: 192.0.2.1\n  interface: en0\n"
        return "  gateway: fe80::1%en0\n  interface: en0\n"
    if destination.startswith("10."):
        return "   route to: 10.1.1.53\n  gateway: 10.0.0.78\n  interface: utun4\n"
    return "  gateway: 192.0.2.1\n  interface: en0\n  flags: <UP,GATEWAY,DONE>\n"


def fake_command_runner(
    proxy_output: str = SCUTIL_PROXY_EMPTY,
    recorded_calls: list[list[str]] | None = None,
):
    """Replacement for CommandLog.run that answers each fixed argv from fixtures."""

    def run(self, argv: list[str], ok_codes: tuple[int, ...] = (0,)) -> str | None:
        assert isinstance(ok_codes, tuple)
        if recorded_calls is not None:
            recorded_calls.append(argv)
        command = argv[0]
        if command.endswith("ifconfig"):
            return IFCONFIG_OUTPUT
        if command.endswith("scutil"):
            return SCUTIL_DNS_OUTPUT if argv[1] == "--dns" else proxy_output
        if command.endswith("dscacheutil"):
            return DSCACHEUTIL_OUTPUT
        if command.endswith("route"):
            return route_output(argv[-1], argv[-2])
        if command.endswith("lsof"):
            return LSOF_OUTPUT
        if command.endswith("/ps"):
            return PS_OUTPUT
        if argv[-1] == "-D":
            return TCPDUMP_DEVICES_OUTPUT
        if argv[-1] == "--version":
            return TCPDUMP_VERSION_OUTPUT
        return ""

    return run


@pytest.fixture
def mac_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Both tcpdump builds present; bare `tcpdump` resolves to Homebrew first."""
    present = {discover.APPLE_TCPDUMP, discover.HOMEBREW_TCPDUMP_CANDIDATES[0]}
    monkeypatch.setattr(
        discover.os,
        "access",
        lambda path, mode: str(path) in present or mode == os.W_OK,
    )
    monkeypatch.setattr(
        discover.shutil,
        "which",
        lambda name: "/opt/homebrew/bin/tcpdump" if name == "tcpdump" else None,
    )
    return tmp_path


# ---------------------------------------------------------------- parsers


def test_interfaces_keep_only_usable_addresses_by_default() -> None:
    interfaces = discover.compact_interfaces(
        discover.parse_interfaces(IFCONFIG_OUTPUT), False
    )
    assert [interface["name"] for interface in interfaces] == ["en0", "utun4"]
    assert interfaces[0] == {
        "name": "en0",
        "ipv4": ["192.0.2.83"],
        "ipv6": ["2001:db8::844c"],
        "status": "active",
    }
    assert interfaces[1]["tunnel"] is True
    assert interfaces[1]["ipv4"] == ["10.0.0.78"]


def test_all_interfaces_includes_idle_interfaces_with_flags() -> None:
    interfaces = discover.compact_interfaces(
        discover.parse_interfaces(IFCONFIG_OUTPUT), True
    )
    assert len(interfaces) == 7
    stf_interface = next(
        interface for interface in interfaces if interface["name"] == "stf0"
    )
    assert stf_interface["flags"] == []
    assert stf_interface["tunnel"] is True


def test_resolvers_strip_padded_keys_and_drop_empty_blocks() -> None:
    resolvers = discover.parse_resolvers(SCUTIL_DNS_OUTPUT)
    assert len(resolvers) == 2
    assert resolvers[0] == {
        "scope": "default",
        "nameservers": ["10.1.1.53", "10.2.2.53"],
        "domains": ["corp.example", "example"],
    }
    assert resolvers[1]["scope"] == "scoped"
    assert resolvers[1]["interface"] == "en0"
    assert resolvers[1]["domains"] == ["localdomain"]


def test_resolution_deduplicates_and_ignores_invalid_addresses() -> None:
    assert discover.parse_resolution(DSCACHEUTIL_OUTPUT) == [
        "2001:db8:1::10",
        "203.0.113.10",
    ]


def test_proxy_reported_only_when_enabled() -> None:
    assert discover.parse_proxy(SCUTIL_PROXY_EMPTY) == {}
    assert discover.parse_proxy(SCUTIL_PROXY_ENABLED) == {
        "http": "proxy.example:8080",
        "pac_url": "http://pac.example/proxy.pac",
    }


def test_capture_devices_drop_disconnected_unless_requested() -> None:
    assert discover.parse_capture_devices(TCPDUMP_DEVICES_OUTPUT, False) == [
        "en0",
        "utun0",
        "lo0",
        "pktap0",
    ]
    assert len(discover.parse_capture_devices(TCPDUMP_DEVICES_OUTPUT, True)) == 7


@pytest.mark.parametrize(
    ("lsof_name", "expected"),
    [
        ("192.0.2.83:1->203.0.113.10:443", "203.0.113.10"),
        ("[2001:db8::844c]:1->[2001:db8::1]:443", "2001:db8::1"),
        ("*:5353", None),
        ("192.0.2.83:1->127.0.0.1:9000", None),
        ("192.0.2.83:1->hostname:443", None),
    ],
)
def test_remote_address_forms(lsof_name: str, expected: str | None) -> None:
    assert discover.remote_address(lsof_name) == expected


# ---------------------------------------------------------------- app grouping


def test_helpers_group_under_outermost_app_and_system_hidden() -> None:
    report = discover.group_apps(
        discover.parse_ps(PS_OUTPUT), discover.parse_lsof(LSOF_OUTPUT), None, False
    )
    assert [app["app"] for app in report["apps"]] == ["Sample Browser", "curl"]
    browser = report["apps"][0]
    assert browser["pids"] == [100, 101]
    assert browser["tcp"] == 3
    assert browser["udp"] == 1
    assert browser["process_names"] == [
        "Sample Browser",
        "Sample Browser Helper (Renderer)",
    ]
    assert browser["remotes"] == ["203.0.113.10", "2001:db8:1::10"]


def test_include_system_shows_system_processes() -> None:
    report = discover.group_apps(
        discover.parse_ps(PS_OUTPUT), discover.parse_lsof(LSOF_OUTPUT), None, True
    )
    system_apps = [app for app in report["apps"] if app.get("system")]
    assert [app["app"] for app in system_apps] == ["networkserviceproxy"]


def test_process_filter_includes_socketless_and_system_matches() -> None:
    process_table = PS_OUTPUT + "  400 /Applications/Quiet.app/Contents/MacOS/Quiet\n"
    quiet_report = discover.group_apps(
        discover.parse_ps(process_table),
        discover.parse_lsof(LSOF_OUTPUT),
        "quiet",
        False,
    )
    assert quiet_report["apps"] == [
        {"app": "Quiet", "pids": [400], "process_names": ["Quiet"], "tcp": 0, "udp": 0}
    ]
    system_report = discover.group_apps(
        discover.parse_ps(PS_OUTPUT),
        discover.parse_lsof(LSOF_OUTPUT),
        "networkservice",
        False,
    )
    assert system_report["apps"][0]["system"] is True


def test_app_and_pid_caps_report_omissions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover, "MAX_APPS", 1)
    monkeypatch.setattr(discover, "MAX_PIDS_PER_APP", 1)
    report = discover.group_apps(
        discover.parse_ps(PS_OUTPUT), discover.parse_lsof(LSOF_OUTPUT), None, False
    )
    assert report["apps_omitted"] == 1
    assert report["apps"][0]["pids_omitted"] == 1


# ---------------------------------------------------------------- end-to-end (mocked)


def test_full_discovery_report(
    mac_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded_calls: list[list[str]] = []
    monkeypatch.setattr(
        discover.CommandLog, "run", fake_command_runner(recorded_calls=recorded_calls)
    )
    report = discover.discover(
        ["app.example", "203.0.113.10"], None, True, False, False, mac_environment
    )

    executables = report["executables"]
    assert executables["bare_tcpdump_resolves_to"] == "/opt/homebrew/bin/tcpdump"
    assert executables["apple"]["version"].startswith("tcpdump version 4.99.1")
    assert executables["homebrew"]["path"] == "/opt/homebrew/opt/tcpdump/bin/tcpdump"
    assert report["capture_devices"] == ["en0", "utun0", "lo0", "pktap0"]
    assert report["dns_resolvers"][0]["nameservers"][0] == {
        "address": "10.1.1.53",
        "gateway": "10.0.0.78",
        "interface": "utun4",
    }
    assert [item["address"] for item in report["targets"][0]["addresses"]] == [
        "2001:db8:1::10",
        "203.0.113.10",
    ]
    assert report["notes"][0].startswith("ipv4_via_tunnel_ipv6_direct")
    assert report["capture_dir"]["writable"] is True
    assert "free_gib" in report["capture_dir"]
    for removed_key in ("proxy", "errors", "vpn", "limits", "evidence"):
        assert removed_key not in report

    route_calls = [
        tuple(call[-2:]) for call in recorded_calls if call[0].endswith("route")
    ]
    assert len(route_calls) == len(set(route_calls)), (
        "each route must be looked up once"
    )
    flattened = [argument for call in recorded_calls for argument in call]
    assert "sudo" not in flattened
    assert "-k" not in flattened
    assert not any(argument.endswith("curl") for argument in flattened)
    assert len(json.dumps(report, separators=(",", ":"))) < 2500


def test_proxy_enabled_adds_field_and_note(
    mac_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        discover.CommandLog,
        "run",
        fake_command_runner(proxy_output=SCUTIL_PROXY_ENABLED),
    )
    report = discover.discover(
        ["app.example"], None, False, False, False, mac_environment
    )
    assert report["proxy"]["http"] == "proxy.example:8080"
    assert any(note.startswith("proxy_enabled") for note in report["notes"])
    assert "network_apps" not in report


def test_target_family_split_flag_and_notes() -> None:
    command_log = discover.CommandLog()
    routes = discover.RouteCache(command_log)
    routes.cache.update(
        {
            "inet6:2001:db8:1::10": {"interface": "en0"},
            "inet:203.0.113.10": {"interface": "utun4"},
        }
    )
    with patch.object(
        discover,
        "resolve_target",
        return_value=(["2001:db8:1::10", "203.0.113.10"], None),
    ):
        targets = discover.discover_targets(command_log, routes, ["split.example"])
    assert targets[0]["family_split"] is True
    notes = discover.split_tunnel_notes(
        {"utun4"}, {"ipv4": {}, "ipv6": {}}, {}, targets
    )
    assert notes[0].startswith("ipv4_via_tunnel_ipv6_direct")
    assert any(note.startswith("target_family_split") for note in notes)


def test_command_failures_are_recorded_not_raised(
    mac_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing_command(argv: list[str], **_keyword_arguments: object) -> None:
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(discover.subprocess, "run", missing_command)
    report = discover.discover(
        ["app.example"], "anything", False, False, False, mac_environment
    )
    assert report["interfaces"] == []
    assert report["targets"][0]["error"] == "resolution command failed"
    assert report["errors"]
    assert all(error["returncode"] is None for error in report["errors"])


def test_command_runner_ok_codes_timeout_and_no_shell() -> None:
    command_log = discover.CommandLog()
    failed_result = subprocess.CompletedProcess([], 1, "", "")
    with patch.object(
        discover.subprocess, "run", return_value=failed_result
    ) as mocked_run:
        assert command_log.run(["/usr/sbin/lsof"], ok_codes=(0, 1)) == ""
        assert command_log.run(["/bin/false"]) is None
        assert (
            mocked_run.call_args.kwargs["timeout"] == discover.COMMAND_TIMEOUT_SECONDS
        )
        assert "shell" not in mocked_run.call_args.kwargs
    with patch.object(
        discover.subprocess, "run", side_effect=subprocess.TimeoutExpired(["x"], 8)
    ):
        assert command_log.run(["/bin/sleep"]) is None
    assert len(command_log.errors) == 2


def test_capture_dir_missing_reports_error(tmp_path: Path) -> None:
    assert (
        discover.discover_capture_dir(tmp_path / "missing")["error"]
        == "not a directory"
    )


# ---------------------------------------------------------------- CLI guards


@pytest.mark.parametrize(
    "value",
    ["example.test", "example.test.", "192.0.2.1", "2001:db8::1", "fe80::1%en0"],
)
def test_target_accepts_hostnames_and_ips(value: str) -> None:
    assert discover.target_value(value) == value


@pytest.mark.parametrize(
    "value", ["", "https://example.test/", "-x", "a;b", "a b", "a..b", "a" * 254]
)
def test_target_rejects_urls_options_and_shell_syntax(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        discover.target_value(value)


def test_output_refuses_skill_folder_and_directories(tmp_path: Path) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        discover.output_path(str(discover.SKILL_ROOT / "discovery.json"))
    with pytest.raises(argparse.ArgumentTypeError):
        discover.output_path(str(tmp_path))


@pytest.mark.parametrize(
    "arguments",
    [
        ["--target", "x.example"] * 17,
        ["--process", " "],
        ["--process", "x" * 129],
        ["--target", "a b"],
    ],
)
def test_cli_rejects_invalid_arguments(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["discover.py", *arguments])
    with pytest.raises(SystemExit) as exit_info:
        discover.main()
    assert exit_info.value.code == 2


def test_cli_rejects_old_python(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["discover.py"])
    monkeypatch.setattr(sys, "version_info", (3, 9, 6, "final", 0))
    assert discover.main() == 2
    error = json.loads(capsys.readouterr().out)
    assert "3.12+" in error["error"]
    assert "3.9.6" in error["error"]


def test_cli_rejects_non_macos(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["discover.py"])
    monkeypatch.setattr(sys, "platform", "linux")
    assert discover.main() == 2
    assert "macOS required" in capsys.readouterr().out


def test_cli_prints_compact_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["discover.py"])
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        discover, "discover", lambda *arguments: {"key": 1, "errors": [{}]}
    )
    assert discover.main() == 0
    assert capsys.readouterr().out.strip() == '{"key":1,"errors":[{}]}'


def test_cli_output_file_is_private_with_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    output_file = tmp_path / "discovery.json"
    monkeypatch.setattr(sys, "argv", ["discover.py", "--output", str(output_file)])
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        discover, "discover", lambda *arguments: {"key": 1, "errors": [{}]}
    )
    assert discover.main() == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "output": str(output_file),
        "bytes": output_file.stat().st_size,
        "errors": 1,
    }
    assert stat.S_IMODE(output_file.stat().st_mode) == 0o600


def test_cli_output_write_failure_exits_3(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def denied(_path: Path, _text: str) -> None:
        raise OSError("permission denied")

    monkeypatch.setattr(
        sys, "argv", ["discover.py", "--output", str(tmp_path / "discovery.json")]
    )
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(discover, "discover", lambda *arguments: {})
    monkeypatch.setattr(discover, "write_private", denied)
    assert discover.main() == 3
