# Repository Audit Matrix

Audit of all candidate repositories for the Unified Wazuh Security Operations Platform.

## Decision Key

| Code | Meaning |
|---|---|
| ✅ | Use directly in Phase 1 |
| ⏳ | Defer to Phase 2/3 |
| 📖 | Reference only (not a direct dependency) |
| ❌ | Rejected (license/risk/incompatible) |
| 🔍 | Needs further investigation |

## Audit Table

| # | Repository | Purpose | Language | License | Stars | Maturity | Security Risk | Integration Value | Phase | Action |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | MCP bridge to Wazuh API/Indexer | Python | MIT | ~182 | Active | Low — read-only tools available | High — 48 Wazuh tools ready | Phase 1 | ✅ **Fork + wrap as adapter** |
| 2 | mcp-server-wazuh (org not found) | Wazuh MCP (Rust) | Rust | — | — | Not found | — | — | — | ❌ **Does not exist** |
| 3 | [gensecaihq/Wazuh-Openclaw-Autopilot](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot) | Autonomous SOC orchestration | JavaScript | MIT | ~34 | Early (1 release) | Medium — autonomous actions | Medium — good reference for workflows | Phase 2 | 📖 **Reference only** |
| 4 | [RyanCodrai/turbovec](https://github.com/RyanCodrai/turbovec) | Vector search/RAG engine | Python/Rust | MIT | ~10.9k | Highly Active | Low | High — best-in-class local RAG | Phase 2 | ⏳ **Defer to Phase 2** |
| 5 | [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 754 cybersecurity skills for AI | Python | Apache 2.0 | ~15.3k | Highly Active | Low | High — SOC playbook knowledge base | Phase 2 | ⏳ **Defer to Phase 2** |
| 6 | [777genius/agent-teams-ai](https://github.com/777genius/agent-teams-ai) | Multi-agent orchestration | TypeScript | AGPL-3.0 | ~1.3k | Highly Active | Low | Medium — patterns useful | Phase 2 | 📖 **Reference only (AGPL)** |
| 7 | [soxoj/maigret](https://github.com/soxoj/maigret) | OSINT username search | Python | MIT | ~32.1k | Very Mature | Medium — external lookups | Low for core SOC | Phase 3 | ⏳ **Defer — needs sandbox** |
| 8 | [GH05TCREW/pentestagent](https://github.com/GH05TCREW/pentestagent) | Autonomous pentesting | Python | MIT | ~2.6k | Active | High — offensive tool | Low for defensive SOC | Future | ❌ **Rejected for Phase 1** |
| 9 | [TencentCloud/CubeSandbox](https://github.com/TencentCloud/CubeSandbox) | MicroVM isolation for AI agents | Rust/Go | Apache 2.0 | ~6.3k | Very Active | Low — sandbox | Medium — isolation layer | Phase 3 | ⏳ **Defer — needs KVM/x86_64** |
| 10 | rtk ecosystem (various) | Token optimization/routing | Rust | MIT | Niche | Active | Low | Low until multi-model | Phase 3 | ⏳ **Defer** |
| 11 | ECC | Developer utility | — | — | — | — | — | — | — | 🔍 **Needs identification** |
| 12 | jcode | Developer utility | — | — | — | — | — | — | — | 🔍 **Needs identification** |

## Key Observations

1. **Wazuh-MCP-Server is the most critical dependency** — it provides ready-made Wazuh API/Indexer tools we can wrap
2. **No suitable mcp-server-wazuh exists** — the Rust-based alternative was not found
3. **agent-teams-ai is AGPL-3.0** — cannot use as a dependency in a commercial product; use patterns only
4. **CubeSandbox requires KVM/x86_64** — won't run on ARM MacBooks or non-KVM EC2 instances
5. **pentestagent and maigret are high-risk for defensive SOC** — must be sandboxed and approval-gated
6. **turbovec + Cybersecurity Skills** will be the foundation of Phase 2 RAG — excellent quality and licensing
