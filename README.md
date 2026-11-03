# llm-skills

Agent Skills in the [agentskills.io](https://agentskills.io/specification) format. Tested with the Pi agent harness.

| Skill | Purpose | Version |
|---|---|---|
| [tcpdump](tcpdump/SKILL.md) | macOS packet capture and pcap/pcapng analysis with tcpdump; Wireshark and tshark requests are translated to tcpdump | 1.3.1 |

## Install

Copy a skill folder into your agent's skills directory, for example `cp -R tcpdump ~/.pi/agent/skills/`. Each skill's `index.md` lists its requirements, files and checksums, and `manifest.sha256` verifies a copy.

## License

MIT. See `LICENSE`.
