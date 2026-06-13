# Phase 3B — Claude: Tiered LLM Routing

## Goal
Route simple alerts to fast/cheap models and complex/critical alerts to powerful models.

## Files to create/modify

### 1. `shared/connectors/llm_router.py` (new)
`TieredRouter` class with scoring-based provider selection:

```python
def get_provider(alert: Alert, tenant_id: str | None) -> LLMProvider:
```

Scoring factors (configurable weights in settings):
- alert.rule_level >= level_threshold → +3
- alert.source_ip in known_bad_ips → +2
- asset_criticality(agent_id) >= high → +2
- rule_historical_accuracy(rule_id) < 0.7 → +2
- MITRE technique in COMPLEX_TECHNIQUES → +1
- is_burst_alert (same rule, same agent, last N min) → -2
- tenant_tier == "premium" → +2
- user_feedback_negative_rate(rule_id) > 0.3 → +2

score >= threshold -> full_provider, else -> fast_provider

### 2. `shared/config.py`
Add routing config:
- llm_tier_strategy: "fast" | "full" | "auto" (default: "auto")
- llm_tier_fast_provider: str (default: "ollama")
- llm_tier_fast_model: str (default: "qwen2.5-coder:3b")
- llm_tier_full_provider: str (default: "ollama")
- llm_tier_full_model: str (default: "qwen2.5-coder:7b")
- llm_tier_level_threshold: int = 10
- llm_tier_score_threshold: int = 4
- llm_tier_burst_window_minutes: int = 10

### 3. `services/worker/app/triage_worker.py`
Replace `get_provider()` with `TieredRouter().get_provider(alert, tenant_id)`
Log which tier was selected per triage run.

### 4. `shared/alert_dedup.py`
Export the burst detection helper so llm_router can use it.
