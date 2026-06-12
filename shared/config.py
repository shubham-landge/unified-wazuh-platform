from pydantic_settings import BaseSettings
from pydantic import SecretStr, Field, field_validator
from typing import List, Optional, Union


class Settings(BaseSettings):
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
    wazuh_api_verify_ssl: bool = False

    wazuh_indexer_url: str = "https://172.16.6.179:9200"
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: SecretStr = SecretStr("")
    wazuh_indexer_verify_ssl: bool = False

    llm_provider: str = "ollama"
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    ollama_fast_model: str = "qwen2.5-coder:3b"

    openai_api_key: Optional[SecretStr] = None
    openai_model: str = "gpt-4o"

    gemini_api_key: Optional[SecretStr] = None
    gemini_model: str = "gemini-2.5-flash"

    claude_api_key: Optional[SecretStr] = None
    claude_model: str = "claude-3-5-sonnet-20241022"

    api_keys: Union[List[str], str] = Field(default_factory=lambda: ["soc-key-001"])

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

    dashboard_allowed_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    poll_interval_seconds: int = 60
    alert_lookback_hours: int = 24
    max_alerts_per_poll: int = 100

    triage_confidence_threshold: float = 0.5
    triage_enabled: bool = True
    mask_sensitive_data: bool = True

    tenant_id: str = "default"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
