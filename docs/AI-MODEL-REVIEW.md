# AI Model Review — Community Platforms

**Date**: 2026-06-17
**Repo**: `shubham-landge/unified-wazuh-platform`

---

## Ollama Registry

| Model | Size | Pulls | Use Case |
|-------|------|-------|----------|
| **OpenNix/wazuh-llama-3.1-8B-v1** | 8B | 511 | Wazuh-specific security log analysis — fine-tuned for our exact use case |
| **mranv/siem-llama-3.1** | 8B | 362 | Advanced Wazuh SIEM log analysis, instruction-following |
| **CyberCrew/notmythos-8b** | 8B | 20.9K | General cybersecurity research, incident response |
| **Arnos/easoc-triage** | — | 5 (new) | Security event triage classification |
| **alpernae/qwen2.5-auditor** | 14B | 663 | Security code review, built on qwen2.5-coder |
| **sylink/sylink** | 8B/32B | 812 | Enterprise cybersecurity AI for SOC operations |

### Recommendation
Replace `qwen2.5-coder:7b` with **`wazuh-llama-3.1-8B-v1`** or **`siem-llama-3.1`** as the primary LLM. These are fine-tuned on Wazuh alert data and will produce higher-quality triage with fewer hallucinations.

---

## HuggingFace

| Model | Size | Downloads | Use Case |
|-------|------|-----------|----------|
| **rogue-security/prompt-injection-jailbreak-sentinel-v2** | 0.6B | 9.71K | Detect prompt injection in LLM inputs |
| **Aira-security/FT-Llama-Prompt-Guard-2** | 70.8M | 394 | Lightweight prompt injection classifier |
| **protectai/deberta-v3-base-prompt-injection** | 0.2B | — | Prompt injection detection |

### Recommendation
Add a **prompt-injection guard model** as a pre-filter before the main LLM. `rogue-security/prompt-injection-jailbreak-sentinel-v2` (0.6B) is small enough to run on CPU and complements our existing `sanitize_llm_input()` function.

---

## GPT / Claude / Gemini (Cloud)

| Model | Strength | Consideration |
|-------|----------|---------------|
| **GPT-4o** | Best general reasoning, large context | Costly, requires internet |
| **Claude Opus 4** | Best SOC analysis, safety | Costly, Anthropic API key needed |
| **Gemini 2.5 Flash** | Fast, good quality | Google Cloud required |

### Recommendation
Keep as a tier-2 fallback (already configured in `.env.example`) for complex triage that exceeds local model capability.

---

## Current configuration
```
LLM_PROVIDER=ollama
OLLAMA_MODEL=qwen2.5-coder:7b
LLM_TIER_FAST_MODEL=qwen2.5-coder:3b
LLM_TIER_FULL_MODEL=qwen2.5-coder:7b
```

## Proposed upgrade path
1. Pull `wazuh-llama-3.1-8B-v1` on the Ollama server: `ollama pull OpenNix/wazuh-llama-3.1-8B-v1`
2. Update `.env`:
   ```
   OLLAMA_MODEL=OpenNix/wazuh-llama-3.1-8B-v1
   LLM_TIER_FAST_MODEL=OpenNix/wazuh-llama-3.1-8B-v1
   LLM_TIER_FULL_MODEL=sylink/sylink:32b
   ```
3. Optional: add `rogue-security/prompt-injection-jailbreak-sentinel-v2` as pre-filter
