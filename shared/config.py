from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, Field, field_validator, model_validator
from typing import List, Optional, Union


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Unified Wazuh SOC Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"
    secret_key: SecretStr

    database_url: str = "postgresql+asyncpg://soc_user:soc_password@postgres:5432/soc_platform"
    database_sync_url: str = "postgresql://soc_user:soc_password@postgres:5432/soc_platform"

    redis_url: str = "redis://:redis_password@redis:6379/0"

    wazuh_api_url: str = "https://172.16.2.130:55000"
    wazuh_api_user: str = ""
    wazuh_api_password: SecretStr = SecretStr("")
    wazuh_api_verify_ssl: bool = True

    wazuh_indexer_url: str = "https://172.16.6.179:9200"
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: SecretStr = SecretStr("")
    wazuh_indexer_verify_ssl: bool = True

    # Multi-manager / multi-indexer configuration.
    # Format per entry: label=url;user;password  (entries comma-separated).
    # When empty, the legacy single-manager/indexer settings above are used.
    wazuh_managers: str = ""
    wazuh_indexers: str = ""

    llm_provider: str = "ollama"
    ollama_base_url: str = "http://ollama:11434"
    # Deep-investigation / long-context tier (escalation only on CPU-only deploys).
    # Full-investigation tier — 128K context, cybersecurity-specialized.
    ollama_model: str = "Foundation-Sec-8B-Instruct"
    # Fast / noise-gate tier — 3b instruct model, CPU-friendly default.
    ollama_fast_model: str = "qwen3:4b-instruct"

    openai_api_key: Optional[SecretStr] = None
    openai_model: str = "gpt-4o"

    gemini_api_key: Optional[SecretStr] = None
    gemini_model: str = "gemini-2.5-flash"

    claude_api_key: Optional[SecretStr] = None
    claude_model: str = "claude-opus-4-8"

    # ── Notification connectors ──
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: Optional[SecretStr] = None
    smtp_use_tls: bool = True
    smtp_from_address: str = "soc-platform@localhost"

    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    pagerduty_routing_key: Optional[SecretStr] = None

    # ── Threat intel connectors ──
    otx_api_key: Optional[SecretStr] = None
    misp_url: str = ""
    misp_api_key: Optional[SecretStr] = None
    misp_verify_ssl: bool = True
    virustotal_api_key: Optional[SecretStr] = None
    ti_feed_poll_interval_seconds: int = 3600

    # ── UEBA ──
    ueba_zscore_medium: float = 2.5
    ueba_zscore_high: float = 3.5
    ueba_zscore_critical: float = 5.0
    ueba_min_observations: int = 10

    # No default — must be set explicitly in .env to prevent accidental open access
    api_keys: Union[List[str], str] = Field(default_factory=list)

    @field_validator('api_keys', mode='before')
    @classmethod
    def parse_api_keys(cls, v):
        if isinstance(v, str):
            if v.startswith('[') and v.endswith(']'):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [x.strip() for x in v.split(',') if x.strip()]
        return v

    # Optional default tenant for legacy API-key callers. If unset, API-key requests
    # without an explicit tenant context are rejected.
    api_key_default_tenant: Optional[str] = None

    api_rate_limit: int = 100
    api_default_page_limit: int = 100

    # Comma-separated allowed CORS origins. Empty = no CORS (API-only, no browser access).
    cors_allowed_origins: str = ""

    dashboard_allowed_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    poll_interval_seconds: int = 60
    vuln_poll_interval_hours: int = 6
    report_retention_days: int = 90
    reports_storage_path: str = "/app/reports"
    alert_lookback_hours: int = 24
    max_alerts_per_poll: int = 100

    triage_confidence_threshold: float = 0.5
    triage_enabled: bool = True
    # Manual "Analyze" button is interactive — force the fast tier by default so
    # the analyst gets a result quickly. Set false to let the router decide.
    triage_manual_force_fast: bool = True
    mask_sensitive_data: bool = True

    # ── Noise reduction (pre-triage stage) ──
    # Deterministic keep/drop/downgrade BEFORE the LLM, to protect CPU-only
    # triage budget. See docs/operations/DEPLOYMENT-PLAN.md §4-5.
    noise_reduction_enabled: bool = True
    # Minimum Wazuh rule level eligible for AI triage (decision: level >= 7).
    triage_min_level: int = 7
    # Rule groups whose alerts are dropped from AI triage (still stored in Wazuh).
    # Comma-separated substrings matched against rule_groups.
    noise_drop_rule_groups: str = ""
    # Specific rule IDs to always drop from AI triage. Comma-separated ints.
    noise_drop_rule_ids: str = ""
    # Rule IDs to downgrade — triaged on the fast tier only, never escalated to 7B.
    noise_downgrade_rule_ids: str = ""
    # After this many duplicate alerts collapse into one incident within the
    # correlation window, suppress re-triage of further duplicates.
    noise_dedup_suppress_after: int = 3
    osint_maigret_url: str = "http://maigret:8080"
    osint_sandbox_timeout: int = 120
    osint_enabled: bool = False

    tenant_id: str = "default"

    # ── Authentication & Authorization ──
    jwt_secret_key: SecretStr = SecretStr("change-me-in-production-minimum-32-chars")
    jwt_expiration_hours: int = 24
    jwt_algorithm: str = "HS256"

    @model_validator(mode="after")
    def _reject_default_secret(self) -> "Settings":
        _default = "change-me-in-production-minimum-32-chars"
        if self.jwt_secret_key.get_secret_value() == _default:
            from os import environ
            env = environ.get("WAZUH_ENV", "").lower()
            if env == "production":
                raise ValueError(
                    "JWT_SECRET_KEY must be overridden in production. "
                    "Set the JWT_SECRET_KEY environment variable."
                )
        return self

    @model_validator(mode="after")
    def _derive_multi_manager_defaults(self) -> "Settings":
        if not self.wazuh_managers:
            pw = self.wazuh_api_password.get_secret_value() if self.wazuh_api_password else ""
            self.wazuh_managers = f"default={self.wazuh_api_url};{self.wazuh_api_user};{pw}"
        if not self.wazuh_indexers:
            pw = self.wazuh_indexer_password.get_secret_value() if self.wazuh_indexer_password else ""
            self.wazuh_indexers = f"default={self.wazuh_indexer_url};{self.wazuh_indexer_user};{pw}"
        return self

    @staticmethod
    def _parse_manager_string(value: str) -> list[dict]:
        if not value:
            return []
        results = []
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "=" in entry:
                label, rest = entry.split("=", 1)
            else:
                label, rest = "default", entry
            parts = rest.split(";")
            results.append(
                {
                    "label": label.strip(),
                    "url": parts[0].strip(),
                    "user": parts[1].strip() if len(parts) > 1 else "",
                    "password": parts[2].strip() if len(parts) > 2 else "",
                }
            )
        return results

    @property
    def parsed_wazuh_managers(self) -> list[dict]:
        return self._parse_manager_string(self.wazuh_managers)

    @property
    def parsed_wazuh_indexers(self) -> list[dict]:
        return self._parse_manager_string(self.wazuh_indexers)

    # OIDC configuration (optional SSO)
    oidc_enabled: bool = False
    oidc_provider_url: str = ""  # e.g. https://accounts.google.com or https://okta.example.com
    oidc_client_id: str = ""
    oidc_client_secret: Optional[SecretStr] = None
    oidc_redirect_uri: str = "http://localhost:8000/auth/callback"
    oidc_scopes: str = "openid,profile,email"

    # Alert deduplication
    alert_dedup_enabled: bool = True
    alert_correlation_window_minutes: int = 120

    # Fingerprint deduplication (fast exact-match pass before AECID)
    fingerprint_dedup_enabled: bool = True

    # Report scheduling
    report_schedule_enabled: bool = True
    schedule_check_interval_seconds: int = 60

    # ── Feedback Loop (Phase 3B) ──
    feedback_enabled: bool = True
    feedback_queue_ttl_hours: int = 720  # 30 days

    # ── RAG / Embeddings (Phase 5A) ──
    embedding_model: str = "nomic-embed-text"
    rag_enabled: bool = True
    rag_top_k: int = 5
    rag_chunk_size: int = 1000
    rag_chunk_overlap: int = 100
    rag_skill_memory_enabled: bool = True

    # ── Ticketing Integrations ──
    servicenow_instance: str = ""
    servicenow_user: str = ""
    servicenow_password: SecretStr = SecretStr("")
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: SecretStr = SecretStr("")
    ticketing_sync_enabled: bool = False

    # ── Usage Metering (Track E) ──
    metering_enabled: bool = True
    metering_retention_days: int = 365
    metering_default_alert_limit: int = 100000
    metering_default_api_limit: int = 500000
    metering_default_storage_gb: int = 10
    metering_default_ai_triage_limit: int = 5000

    # ── Tiered LLM Routing (Phase 3B) ──
    llm_tier_strategy: str = "auto"  # "fast" | "full" | "auto"
    llm_tier_fast_provider: str = "ollama"
    llm_tier_fast_model: str = "qwen3:4b-instruct"   # 1.9GB, fast noise-gate tier
    llm_tier_full_provider: str = "ollama"
    llm_tier_full_model: str = "Foundation-Sec-8B-Instruct"  # 2.0GB, 128K context, cybersecurity-specialized
    llm_tier_level_threshold: int = 10
    llm_tier_score_threshold: int = 4

    # ── Cloud escalation tier (deep analysis for the hardest cases) ──
    # Local qwen (fast) → notmythos (full) stay always-on CPU tiers. Escalation is
    # opt-in: only cross-domain/advancing incidents or very high routing scores go
    # to the cloud, so the CPU-only baseline holds and cloud cost stays bounded.
    llm_tier_escalation_enabled: bool = False
    llm_tier_escalation_provider: str = "gemini"
    llm_tier_escalation_model: str = "gemini-2.5-flash"
    llm_tier_escalation_score_threshold: int = 7
    llm_tier_burst_window_minutes: int = 10
    llm_tier_known_bad_ips: str = ""  # comma-separated
    llm_tier_complex_techniques: str = "T1569.002,T1059.001,T1021.001,T1485,T1490"  # lateral movement, ransomware, etc.

    # ── Model Parameters (applied to all Ollama calls) ──
    llm_model_temperature: float = 0.35
    llm_model_top_p: float = 0.9
    llm_model_top_k: int = 40
    llm_model_repeat_penalty: float = 1.15

    # ── LLM Stability (CPU-only hardening) ──
    # Keep the model resident in Ollama between requests. Without this the 8B
    # unloads after ~5 min idle and every cold request pays a 1-2 min load
    # penalty — the main source of latency variance. "-1" = keep forever,
    # "30m" = keep 30 minutes. Set to "0" only if RAM-constrained.
    ollama_keep_alive: str = "30m"
    # Max concurrent LLM inferences. CPU-only Ollama serializes internally, so
    # >1 just piles up timeouts and risks OOM from parallel model loads. Keep 1.
    llm_max_concurrency: int = 1
    # Cap generated tokens so a runaway response can't double the latency.
    llm_num_predict: int = 1024
    # Explicit context window (notmythos/qwen real ceiling is ~8192 on CPU).
    llm_num_ctx: int = 8192
    # Retries on transient timeout/connection errors before giving up.
    llm_max_retries: int = 1

    # ── Triage DLQ ──
    dlq_max_retries: int = 3
    dlq_poll_interval: int = 5

    # ── ARQ Durable Queue ──
    queue_backend: str = "legacy"  # "arq" or "legacy"; arq replaces DLQ+reaper
    arq_max_tries: int = 3
    arq_keep_result_seconds: int = 3600

    # ── Semantic result cache (Phase P0-5) ──
    triage_cache_enabled: bool = True
    triage_cache_ttl_seconds: int = 1800
    triage_cache_similarity_threshold: float = 0.92
    triage_cache_skip_level: int = 12

    # ── Prompt Template Loading ──
    prompts_path: str = "/app/prompts"  # directory for per-model .md prompt templates

    # ── Dashboard Admin Credentials ──
    dashboard_admin_email: str = ""
    dashboard_admin_password: SecretStr = SecretStr("")

    # ── Credential Leak Monitoring ──
    credential_leak_monitor_enabled: bool = False
    credential_leak_hibp_api_key: Optional[SecretStr] = None
    credential_leak_monitored_emails: str = ""  # comma-separated
    credential_leak_monitored_domains: str = ""  # comma-separated
    credential_leak_check_interval_seconds: int = 86400

    # ── Agent Personas ──
    # Path to agents/ directory containing persona markdown files.
    # Each file declares: agent_type, autonomy_level, model_tier, risk_class, tools.
    agents_personas_path: str = "/app/agents"
    # Default autonomy level applied to any agent type without an explicit persona file.
    # Values: read-only | approval | full
    agent_default_autonomy_level: str = "read-only"
    # Comma-separated list of agent types allowed to run in "full" autonomy (no human gate).
    agent_full_autonomy_types: str = "triage,correlation"

    # ── Wazuh Environment Health Monitoring ──
    # The overlay watches Wazuh itself (agents, manager/cluster, indexer/ingestion)
    # plus our own pipeline, and raises alerts when Wazuh's own health degrades.
    wazuh_health_enabled: bool = True
    wazuh_health_poll_interval_seconds: int = 120
    # Warn when this fraction of enrolled agents are disconnected (0.2 = 20%).
    wazuh_health_agent_disconnect_pct_warn: float = 0.2
    # Warn when newest alert is older than this many seconds (ingestion stalled).
    wazuh_health_ingestion_lag_warn_seconds: int = 600
    # Warn when analysisd dropped at least this many events since last poll.
    wazuh_health_events_dropped_warn: int = 100

    # ── Triggers (Suna-inspired cron + webhook automation) ──
    # Cron triggers: spawn agent sessions on schedule.
    # Format: cron_expression;agent_type;description  (comma-separated list)
    # Example: "0 2 * * *;meta_agent;Nightly missed-detection scan"
    triggers_cron: str = ""
    # Webhook triggers: spawn agents when an external event fires.
    # Format: path_secret;agent_type;description  (comma-separated list)
    # Example: "siem-webhook-a1b2c3;triage;External SIEM webhook"
    triggers_webhooks: str = ""
    # Auto-approve actions from agents at or above this autonomy level.
    triggers_auto_approve_autonomy: str = "full"

    # ── Webhook / Push Ingestion ──
    # When False, POST /alerts/event returns 404 to prevent accidental exposure.
    webhook_ingest_enabled: bool = False

    # ── Alert Enrichment Pipeline (S0 Orchestrator) ──
    # Timeout per individual enricher in seconds (fail-open).
    enrichment_timeout_seconds: int = 10
    # Risk-scoring additive weights (should sum to ~100 for intuitive 0-100 scale).
    enrichment_risk_weight_ti: float = 25
    enrichment_risk_weight_asset: float = 15
    enrichment_risk_weight_user: float = 20
    enrichment_risk_weight_ueba: float = 25
    enrichment_risk_weight_rule_level: float = 15
    # Decision mode: shadow=True logs L0-L4 but never enforces (safe rollout).
    enrichment_decision_shadow_mode: bool = True
    # Global kill switch — when True, enrichment + decision are disabled entirely.
    enrichment_kill_switch: bool = False
    # Per-enricher feature flags.
    enricher_geoip_enabled: bool = False
    enricher_vuln_correlate_enabled: bool = False
    enricher_watchlists_enabled: bool = False
    # ── Incident Risk & Auto-Case ──
    # Cumulative incident risk: when an incident's total risk exceeds this
    # threshold, auto-create a case (shadow mode still logs only).
    incident_auto_case_threshold: float = 150.0
    # Window (hours) for cumulative risk calculation.
    incident_risk_window_hours: int = 24
    # Enable cumulative incident risk tracking.
    incident_risk_enabled: bool = True

    # ── Enrichment Engine (P1/P2 shared/enrichment/) ─────────────────────────
    # Automation mode: "shadow" = log decisions, no action; "enforce" = act.
    automation_mode: str = "shadow"

    # Containment gate settings
    containment_score_threshold: int = 60
    containment_crown_jewel_requires_approval: bool = True
    containment_ti_override_actions: list[str] = ["isolate_host", "block_ip"]

    # L0-L4 decision gate thresholds
    risk_gate_l0_threshold: int = 15    # below → suppress (no LLM)
    risk_gate_l1_threshold: int = 25    # below → auto-close (no LLM)
    risk_gate_l2_upper_threshold: int = 60  # above → auto-escalate
    risk_gate_l3_threshold: int = 85    # above → critical

    # Auto-close pipeline
    auto_close_score_threshold: int = 25
    auto_close_confidence_threshold: float = 0.85
    auto_close_enabled: bool = True

    # GeoIP database paths (MaxMind GeoLite2)
    geoip_city_db_path: str = "/opt/geoip/GeoLite2-City.mmdb"
    geoip_asn_db_path: str = "/opt/geoip/GeoLite2-ASN.mmdb"

    # Risk weight overrides (all have built-in defaults; override via env)
    risk_weight_rule_level_critical: float = 40.0
    risk_weight_rule_level_high: float = 30.0
    risk_weight_rule_level_medium_high: float = 20.0
    risk_weight_rule_level_medium: float = 10.0
    risk_weight_ti_known_bad: float = 40.0
    risk_weight_ti_base: float = 30.0
    risk_weight_asset_criticality_per_point: float = 2.0
    risk_weight_vuln_kev_epss: float = 35.0
    risk_weight_vuln_matched: float = 25.0
    risk_weight_ueba_critical: float = 20.0
    risk_weight_ueba_high: float = 12.0
    risk_weight_ueba_medium: float = 6.0
    risk_weight_ueba_zscore_critical_threshold: float = 5.0
    risk_weight_ueba_zscore_high_threshold: float = 3.5
    risk_weight_ueba_zscore_medium_threshold: float = 2.5
    risk_weight_user_privileged: float = 10.0
    risk_weight_user_service_acct: float = 10.0
    risk_weight_user_dormant: float = 15.0
    risk_weight_geo_impossible_travel: float = 15.0
    risk_weight_geo_tor_vpn: float = 8.0
    risk_weight_geo_bad_asn: float = 5.0
    risk_weight_geo_unexpected_country: float = 5.0
    risk_weight_mitre_high_impact: float = 10.0
    risk_weight_confirmed_fp_penalty: float = 20.0
    risk_weight_benign_noise_penalty: float = 10.0
    risk_weight_crown_jewel_multiplier: float = 1.3

    # ── Eval Harness ─────────────────────────────────────────────────────────
    eval_dataset_path: str = "tests/fixtures/triage_eval"
    eval_output_path: str = "reports/eval"

settings = Settings()


def require_tenant_uuid():
    """Resolve the configured default tenant or raise if unset.

    Server-side ingestion paths (poller, credential-leak worker) that have
    no request tenant context **must** have a configured default tenant.
    """
    import uuid

    raw = settings.api_key_default_tenant
    if not raw:
        raise ValueError(
            "API_KEY_DEFAULT_TENANT is not configured. "
            "Set this environment variable to a valid tenant UUID for server-side ingestion."
        )
    try:
        return uuid.UUID(str(raw))
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"API_KEY_DEFAULT_TENANT '{raw}' is not a valid UUID."
        ) from exc


default_tenant_uuid = require_tenant_uuid
