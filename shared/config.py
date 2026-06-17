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
    ollama_model: str = "qwen2.5:7b-instruct"
    # Primary triage tier — small instruct model, CPU-friendly default.
    ollama_fast_model: str = "qwen2.5:3b-instruct"

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
    llm_tier_fast_model: str = "notmythos:mini"     # 398MB, 32K context, cybersecurity-specialized
    llm_tier_full_provider: str = "ollama"
    llm_tier_full_model: str = "notmythos:8b"       # 2.0GB, 128K context, cybersecurity-specialized
    llm_tier_level_threshold: int = 10
    llm_tier_score_threshold: int = 4
    llm_tier_burst_window_minutes: int = 10
    llm_tier_known_bad_ips: str = ""  # comma-separated
    llm_tier_complex_techniques: str = "T1569.002,T1059.001,T1021.001,T1485,T1490"  # lateral movement, ransomware, etc.

    # ── Model Parameters (applied to all Ollama calls) ──
    llm_model_temperature: float = 0.35
    llm_model_top_p: float = 0.9
    llm_model_top_k: int = 40
    llm_model_repeat_penalty: float = 1.15

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
