---
type: report
title: tcpdump skill 1.3.1 validation record
description: Executed and pending checks for the tcpdump skill bundle, by artifact and environment. Maintainer file; not loaded by the agent.
resource: index.md
tags: [tcpdump, agent-skill, validation]
okf_version: "0.2"
status: draft
generated: 2026-11-02T18:06:02-08:00
verified: false
sources:
  - id: bundle-index
    resource: index.md
    title: Bundle index with file hashes
  - id: evals
    resource: evals/evals.json
    title: Output evals and trigger queries
---

# tcpdump skill 1.3.1 validation record

1.3.1 changed wording in `capture.md`, `builds.md` and `discovery.md` only; all other files are byte-identical to 1.3.0, so their results carry over. Only checks that actually ran are listed as executed, with the environment named. Everything else is pending. Maintenance commands are in `index.md`.

[Environments](#environments) | [Status by artifact](#status-by-artifact) | [Executed: discover.py and tests](#executed-discoverpy-and-tests) | [Executed: agent environment](#executed-agent-environment) | [Executed: documents](#executed-documents) | [Packaging](#packaging) | [Pending](#pending)

## Environments

| ID | Environment |
|---|---|
| SANDBOX | Linux x86_64, Python 3.12.15; ruff 0.17.3, ty 0.0.95, pytest 9.2.0, coverage 7.17.0, bandit 1.9.4, vulture 2.16. No macOS commands, no tcpdump |
| MAC | macOS 26.7.2 (25G332) arm64, zsh 5.9.2, Python 3.14.10 (uv); same tool versions; Apple tcpdump 4.99.1 (Apple version 158), Homebrew tcpdump 4.99.7 |
| PI | Pi agent harness v1.5.0 on MAC, permission mode Inspect, shell bash |

## Status by artifact

| Artifact | Generated | Validated | Accepted |
|---|---|---|---|
| `scripts/discover.py` v2.0.3 | 2026-11-02 | SANDBOX pass; MAC pass (1.3.0 install check) | Yes |
| `tests/test_discover.py` | 2026-11-02 | SANDBOX pass; MAC pass (1.3.0 install check) | Yes |
| `SKILL.md` | 2026-11-02 | SANDBOX structural pass; PI behavior pending | Yes |
| `references/builds.md` | 2026-11-02 (1.3.1 wording) | SANDBOX pass against bundled manuals; links pass | Yes |
| `references/capture.md` | 2026-11-02 (1.3.1 wording) | SANDBOX syntax and link pass; MAC zsh and live capture pending | Yes |
| `references/interpretation.md` | 2026-11-02 | SANDBOX pass against bundled manuals | Yes |
| `references/discovery.md` | 2026-11-02 (1.3.1 wording) | SANDBOX pass against mocked discovery output | Yes |
| `references/wireshark-equivalents.md` | 2026-11-02 | SANDBOX pass on synthetic text; MAC real-capture pending | Yes |
| `evals/evals.json` | 2026-11-02 | SANDBOX structure pass; not yet run | Yes |
| `index.md` | 2026-11-02 | SANDBOX hash and link pass | Yes |
| `validation.md` | 2026-11-02 | This file | Yes |
| Bundle archive `tcpdump-1.3.1.zip` | 2026-11-02 | SANDBOX pass (see Packaging) | Pending |

"Applied" (installed in the agent's skill directory) is pending for every artifact until the packaged bundle is installed.

## Executed: discover.py and tests

| Check | SANDBOX | MAC |
|---|---|---|
| Hashes | v2.0.3: discover.py `bc791224…`, tests `866b9e2f…` | v2.0.2: discover.py `37ad0890…`, tests `6150e9aa…` |
| `ruff format --check`, `ruff check` (default rules) | Pass | Pass |
| `ty check --error all --ignore truthiness-test-of-none-union` (scripts and tests) | Pass, Python 3.12 and 3.14 targets | Pass, Python 3.14 |
| `ty check --error all` with that rule enabled | 19 diagnostics, all `truthiness-test-of-none-union`; reviewed, `None` and `""` both intentionally mean "no data" | Not run |
| pytest | 43 passed | 43 passed |
| Branch coverage of discover.py | 92% | 92% |
| Bandit, discover.py | B404, B603 (low, reviewed: fixed argv lists, no shell) | Same |
| Bandit, tests (B101 skipped) | B404 (low) | Same |
| Vulture `--min-confidence 0` | Clean | Clean |
| Real discovery run, no options (v2.0.2 and v2.0.3) | Not possible | rc 0, 1,432 bytes, 0 errors |
| 1.3.0 install check (manifest, ruff, ty strictest, pytest 43, coverage 92%, bandit, vulture, smoke) on v2.0.3 | Pass | Pass |
| Real discovery run with `--network-apps --target example.com` (v2.0.1) | Not possible | rc 0, 4,064 bytes, file mode `-rw-------`, 0 errors; both builds found, `bare_tcpdump_resolves_to` Homebrew; interfaces reduced to en0 and utun4; corporate nameservers routed via utun4, home nameservers via en0; `ipv4_via_tunnel_ipv6_direct` note raised; apps grouped by bundle with no browser names in code |
| Apple `/usr/bin/python3` 3.9.6 refused (v2.0.0) | Mocked test passes | rc 2 with "Python 3.12+ required" message |
| Stray artifacts after QA | None | None |

v2.0.1 and v2.0.2 changed only typing (`len()` guard, `str()` on a regex group). v2.0.3 changed only the header timestamp (corrected to 2026-11-02T16:39:57-08:00), the usage example (`getconf` fallback for `$TMPDIR`) and the wording of the `--output` error; the test file changed only its header timestamp. SANDBOX reran the full suite on v2.0.3 with identical results. Behavior is unchanged from the MAC runs above.

## Executed: agent environment

| Check | Result (PI) |
|---|---|
| `python3` in Pi's shell | `/opt/homebrew/opt/python@3.14/libexec/bin/python3`, 3.14.10 |
| `$TMPDIR` in Pi's shell | `/tmp/pi/<session-id>`: differs from the user's terminal |
| `getconf DARWIN_USER_TEMP_DIR` in Pi's shell | Same `/var/folders/.../T/` path as the terminal |
| Per-user temp folder readable from Pi | Yes (`drwx------`, owner matches) |
| Shell used by Pi for commands | bash |

These results set the design: captures use `getconf DARWIN_USER_TEMP_DIR`; agent-run commands must work in bash.

## Executed: documents

| Check | Result (SANDBOX) |
|---|---|
| `SKILL.md` frontmatter: valid YAML, `name` matches folder, description 683 chars, compatibility 129 chars | Pass |
| `SKILL.md` size | 67 lines, about 1,150 tokens; references 1,000 to 1,600 tokens each |
| Relative links from `SKILL.md` and between references | Pass; all one level deep |
| In-page anchors in all Markdown files | Pass |
| Shell blocks in `SKILL.md`, `capture.md`, `discovery.md`, `wireshark-equivalents.md` (`bash -n`) | Pass |
| Read-back commands in `capture.md` start with `-r` (matches `allowed-tools`) | Pass |
| `builds.md` and `interpretation.md` build-specific claims vs v1.2.0 manual copies | Pass: `--count` stderr (Apple) vs stdout (Homebrew); `pktap,all` includes tunnel and loopback; default capture excludes them; interface-prefix matching; RAW gives legacy pcap; default snaplen 262144; counter meanings; `tcp[0]` IPv4-only; `-K`; `-tttt` |
| `discovery.md` field names and `jq` examples vs mocked v2.0.2 output | Pass |
| `wireshark-equivalents.md` text pipelines on synthetic IPv4/IPv6 lines | Pass: conversations, endpoints, per-second and per-minute buckets, flags, duplicate sequence ranges |
| `evals/evals.json` | Valid JSON; 5 evals with 4 to 6 assertions; 20 trigger queries, 10/10, split 6/4 per class |
| `index.md` hashes vs current files | Pass, 0 mismatches |
| Project-specific terms (browser names, organization hosts, SAML/AWS, Downloads) in agent-facing files | None |

## Packaging

| Check | Result (SANDBOX) |
|---|---|
| Built from the user-uploaded 1.3.0 archive (`tcpdump-1.3.0.zip.txt`, SHA-256 `e3dfb511b49855ba7f78023f65768e2a326f22fa2ca36ef2dcff8595ba798184`); manifest verified before the 1.3.1 edits | Pass |
| `manifest.sha256` covers every file except itself; `shasum -a 256 -c` style verification on a clean extraction | Pass |
| ZIP: standard Deflate level 9, no `__MACOSX`, `.DS_Store` or extended attributes; `discover.py` mode 755 | Pass |
| Clean extraction: ruff, pytest (43 passed), links and anchors | Pass |

## Pending

| Check | Environment | How |
|---|---|---|
| `zsh -n` on capture blocks in `capture.md` | MAC | Extract the zsh blocks and run `zsh -n` |
| Live capture with `-i pktap,all` and `--apple-md-filter` writing to the `getconf` folder | MAC (user-run sudo) | Use the capture.md template; confirm file path printed, pcapng written, `-r` readable without sudo |
| Wireshark-equivalents recipes on a real capture (line layout with `-nn -q` and `-tttt -q`, including pcapng with metadata) | MAC | Run the local check in that file |
| Homebrew `-i any` on macOS | MAC | Check `-D` and a short capture; currently undocumented in `-D` output |
| `allowed-tools` effect in Pi (whether enforced, whether patterns with spaces parse) | PI | Observe prompts for `discover.py` and `tcpdump -r` |
| Trigger evals: 20 queries, 3 runs each, threshold 0.5; train then validation split | PI | `jq` extract from `evals/evals.json`, run in fresh sessions, record trigger rates here |
| Output evals 1 to 5, with and without the skill | PI | Fresh session per run; grade assertions with evidence; record pass rates, tokens and time here |
| `skills-ref validate` | MAC | If installed; not required |
| Install from `tcpdump-1.3.1.zip` and `shasum -a 256 -c manifest.sha256` | MAC | Install block delivered with the archive |
