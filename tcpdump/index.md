---
type: index
title: tcpdump agent skill for macOS
description: Bundle index for the tcpdump skill. File inventory, install steps, maintainer commands and provenance. Not loaded by the agent during tasks.
resource: SKILL.md
tags: [tcpdump, agent-skill, macos, packet-capture]
okf_version: "0.2"
status: draft
generated: 2026-11-02T18:06:02-08:00
verified: false
sources:
  - id: agent-skills-spec
    resource: https://agentskills.io/specification
    title: Agent Skills specification
  - id: predecessor-1-2-0
    resource: tcpdump.zip.txt
    title: tcpdump skill v1.2.0 archive (SHA-256 3428c9e3f50411249c3f1a717cece7ffbb3a3e1f070bf6c54ec18451f4f098c6)
  - id: apple-manual
    resource: /usr/share/man/man1/tcpdump.1
    title: Apple tcpdump manual, footer 21 December 2020 (tcpdump 4.99.1, Apple version 158)
  - id: homebrew-manual
    resource: /opt/homebrew/opt/tcpdump/share/man/man1/tcpdump.1
    title: Homebrew tcpdump manual, footer 2 February 2026 (tcpdump 4.99.7)
---

# tcpdump agent skill for macOS

Bundle version 1.3.1. Maintainer index; the agent starts at `SKILL.md` and never needs this file. Verify the bundle with `shasum -a 256 -c manifest.sha256` from the skill root.

[Install](#install) | [Files](#files) | [Maintenance](#maintenance) | [Provenance](#provenance) | [Changes in 1.3.1](#changes-in-131) | [Changes in 1.3.0](#changes-in-130)

## Install

Copy the whole `tcpdump` folder into a skill directory your agent scans, keeping `SKILL.md` at the folder root. For Pi, the global location is `~/.pi/agent/skills/`:

```zsh
mkdir -p ~/.pi/agent/skills
cp -R tcpdump ~/.pi/agent/skills/
chmod 755 ~/.pi/agent/skills/tcpdump/scripts/discover.py
```

Restart the agent so it rereads skill names and descriptions. Requirements: macOS, `python3` 3.12 or newer on the agent's PATH, Apple `/usr/sbin/tcpdump` (built in) and optionally Homebrew `tcpdump`. Nothing is installed automatically.

## Files

| Path | Loaded by agent | Purpose | SHA-256 |
|---|---|---|---|
| `SKILL.md` | On activation | Workflow, build choice, gotchas | `ea262ef80240d1d624219223c15dcfe27bd8fd55c5f164302d9d9cf0fb116c5a` |
| `references/builds.md` | On demand | Apple vs Homebrew options, metadata, manual lookup | `607a3f3198e707346af26abd8bbf44cf63f902c265842e99ee2ffc58ce7162ff` |
| `references/capture.md` | On demand | Command building, sudo handoff, read-back | `21fed2d2e9499a65908ec5a14a86ba2465d31d7a9588f59d0fc262ea598d22ec` |
| `references/interpretation.md` | On demand | Counters, empty captures, evidence limits, report | `0c0098267ac94bcc1bcd5890c05709bc63349a95146fa8f8e00447a22cd061e0` |
| `references/discovery.md` | On demand | discover.py options, JSON fields, exit codes | `29d9dd012cf57a6f683c5c915b96ae25ddea2deb279a3b3b553f0c0fb0d15885` |
| `references/wireshark-equivalents.md` | On demand | Wireshark/tshark requests translated to tcpdump | `9b9ae371e810f6e7d928c0f781808073b6f780f0b614697a1964b201d6ed3cdf` |
| `scripts/discover.py` | Executed, not read | Read-only discovery, schema 2.0, v2.0.3 | `bc7912245438497c8ce4e518dfe46ea051b01081eddc2a9413ae6ed09a8915d6` |
| `tests/test_discover.py` | No | Unit tests for discover.py (maintainer) | `866b9e2fe87c1191dcf6a468b844baad2719f1b665f2c8be6d184eda7a8059df` |
| `evals/evals.json` | No | Output evals and trigger queries (maintainer) | `324a777353cb958cbff9b6b2ea45d43fb6298a13fa67f5c1a340d2fe6d54818e` |
| `validation.md` | No | Executed and pending checks (maintainer) | See `manifest.sha256` |
| `index.md` | No | This file | See `manifest.sha256` |
| `manifest.sha256` | No | SHA-256 of every file except itself | n/a |

## Maintenance

Run from the skill root. These use uv-managed tools so nothing is added to the skill folder; caches and coverage data go to the per-user temp folder.

```zsh
tmp_root="$(getconf DARWIN_USER_TEMP_DIR)"
export COVERAGE_FILE="${tmp_root%/}/tcpdump-skill.coverage" PYTHONDONTWRITEBYTECODE=1
qa=(uv run --no-project --python 3.14 --with pytest --with coverage --with ruff --with ty --with bandit --with vulture)
$qa ruff format --check --no-cache scripts tests
$qa ruff check --no-cache scripts tests
$qa sh -c 'ty check --python-version 3.14 --error all --ignore truthiness-test-of-none-union --extra-search-path scripts --extra-search-path "$(python -c "import os,pytest;print(os.path.dirname(os.path.dirname(pytest.__file__)))")" scripts tests'
$qa sh -c 'coverage run --branch --include=scripts/discover.py -m pytest -q -p no:cacheprovider tests && coverage report | tail -1'
$qa bandit -q scripts/discover.py
$qa bandit -q -s B101 tests/test_discover.py
$qa vulture --min-confidence 0 scripts tests
```

Expected: all `rc=0` except Bandit, which reports only B404 and B603 (low, reviewed) on the script and B404 on the tests. Results and dates are in `validation.md`.

Trigger and output evals: see `evals/evals.json`. Extract the train split for a trigger-rate script with:

```zsh
jq '[.trigger_queries[] | select(.split=="train") | {query, should_trigger}]' evals/evals.json
```

When updating: keep `SKILL.md` under 500 lines and 5,000 tokens, keep references one level deep, and update this file's hashes, `validation.md` and `manifest.sha256` together.

## Provenance

- Agent-facing content was written from the installed Apple and Homebrew tcpdump manuals listed in `sources`, observed output from the maintainer's Mac (macOS 26.7.2, arm64), and the Agent Skills specification and best-practice guides.
- Build-specific claims in `references/builds.md` were checked against manual copies bundled in v1.2.0. Those copies (`tcpdump-apple-man.txt` SHA-256 `d1cb0382d952272f52b0213a09a9d485684f571eb42c95baa965b31d12dcd91d`, `tcpdump-homebrew-man.txt` SHA-256 `e28f25a76149b6d66c3196582a92bd3beb1db991dd03f29af06aa552dcfcb0c7`) are removed in 1.3.0; the agent reads the installed manuals instead. They remain recoverable from the predecessor archive.
- All addresses in examples and tests are documentation-reserved (RFC 5737, RFC 3849). No real captures, PIDs or organization-specific hosts are included.

## Changes in 1.3.1

Wording only; no change to `SKILL.md`, `discover.py`, tests or evals.

- `capture.md`: second capture template replaced by a one-line variant; handoff rule cut to `exit` and `&`; empty-capture guidance points to `interpretation.md` instead of repeating it.
- `builds.md`: provenance sentence shortened.
- `discovery.md`: Run section points to `SKILL.md` step 2 instead of repeating the command.

## Changes in 1.3.0

- **Discovery rewritten (v2.0.3):** compact JSON with only decision-relevant fields; interfaces filtered to usable addresses; nameserver routes; IPv4/IPv6 split notes; proxy detection; generic app grouping by `.app` bundle (no browser names); capture-folder space check; owner-only `--output`; resolver key-padding bug fixed; plain `python3` (3.12+), no uv.
- **SKILL.md rewritten:** numbered workflow, literal build paths, gotchas, Wireshark/tshark requests routed to tcpdump, `compatibility` and `allowed-tools` frontmatter.
- **References consolidated** from 9 to 5. Captures use the per-user temp folder from `getconf DARWIN_USER_TEMP_DIR`, because agent harnesses may set their own `$TMPDIR`.
- **Removed:** bundled manual copies, `agents/ui_metadata.yaml` (not in the Agent Skills spec), project-specific guidance (VPN incident, HTTP/SAML/AWS, browser names, personal report preferences), and merged reference files.

| Removed in 1.3.0 | Replaced by | v1.2.0 SHA-256 |
|---|---|---|
| `references/apple-metadata.md` | `builds.md` | `bd529c9862550382804c7132145d36f9d3f5fd3139e8c3ff687b6bb0e879114f` |
| `references/homebrew.md` | `builds.md` | `415cbf143943754df343d850eff199390ed189ab359f0f9e6d697d2bd3362e4e` |
| `references/shared.md` | `builds.md`, `capture.md` | `cbd7b0a9bc57ca55da83d8a786f72a3b538aa8aeacbdf3a9e4a1d642e25147aa` |
| `references/manual-locator.md` | `builds.md` | `181a41a21b299a8c98eaeb2b4c86f3d28a875ad4bef7fc76133a27eb5969069b` |
| `references/commands.md` | `capture.md` | `12e20f3677464a8cff441281b09ee2f9321ca8a86c8d562a873addb4185a132d` |
| `references/interaction.md` | `capture.md` | `c9d278cf9142ad012e42177fe1924b89107d9444f81c7cb4fbb914c989c521c3` |
| `references/evaluation.md` | `evals/evals.json` | `00b81f3a5306806a25cbc908d1fc9f8dd780c9efa73464b1131cdd7b1ca0c057` |
| `references/validation.md` | `validation.md` (root) | `d193c3a7bc49738eab9a4a04a1e694e58fd83831c955e0b4a0eb8d4c5f07a63a` |
| `references/tcpdump-apple-man.txt` | Installed manual | `d1cb0382d952272f52b0213a09a9d485684f571eb42c95baa965b31d12dcd91d` |
| `references/tcpdump-homebrew-man.txt` | Installed manual | `e28f25a76149b6d66c3196582a92bd3beb1db991dd03f29af06aa552dcfcb0c7` |
| `agents/ui_metadata.yaml` | None | `9da149c3966322fba867c4bb249e0fefa7218bc8208bb1c3a7f7ee650bde19ea` |
