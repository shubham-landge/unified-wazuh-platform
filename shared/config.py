from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, Field, field_validator
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

    llm_provider: str = "ollama"
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    ollama_fast_model: str = "qwen2.5-coder:3b"

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

    api_rate_limit: int = 100

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

    tenant_id: str = "default"

    # ── Authentication & Authorization ──
    jwt_secret_key: SecretStr = SecretStr("change-me-in-production-minimum-32-chars")
    jwt_expiration_hours: int = 24
    jwt_algorithm: str = "HS256"

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

    # ── Tiered LLM Routing (Phase 3B) ──
    llm_tier_strategy: str = "auto"  # "fast" | "full" | "auto"
    llm_tier_fast_provider: str = "ollama"
    llm_tier_fast_model: str = "qwen2.5-coder:3b"
    llm_tier_full_provider: str = "ollama"
    llm_tier_full_model: str = "qwen2.5-coder:7b"
    llm_tier_level_threshold: int = 10
    llm_tier_score_threshold: int = 4
    llm_tier_burst_window_minutes: int = 10
    llm_tier_known_bad_ips: str = ""  # comma-separated
    llm_tier_complex_techniques: str = "T1569.002,T1059.001,T1021.001,T1485,T1490"  # lateral movement, ransomware, etc.

settings = Settings()
