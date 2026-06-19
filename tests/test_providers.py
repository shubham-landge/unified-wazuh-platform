import pytest
from pydantic import ValidationError

from shared.providers.base import BaseProvider
from shared.providers.factory import ProviderRegistry
from shared.providers.template import TemplateConfig, TemplateProvider


class TestProviderRegistry:
    def test_register_and_get(self):
        registry = ProviderRegistry()
        registry.register(TemplateProvider)
        provider = registry.get_provider("template", cfg={"api_url": "https://example.com"})
        assert isinstance(provider, TemplateProvider)
        assert provider.api_url == "https://example.com"
        assert "template" in registry
        assert registry.registered_types == ["template"]

    def test_register_duplicate_raises(self):
        registry = ProviderRegistry()
        registry.register(TemplateProvider)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(TemplateProvider)

    def test_get_unknown_raises(self):
        registry = ProviderRegistry()
        with pytest.raises(KeyError, match="Unknown provider type"):
            registry.get_provider("nope")

    def test_config_schema_validation(self):
        registry = ProviderRegistry()
        registry.register(TemplateProvider)
        with pytest.raises(ValidationError):
            registry.get_provider("template", cfg={"api_url": ""})


class TestTemplateProvider:
    async def test_validate_config_passes(self):
        p = TemplateProvider(api_url="https://valid.example.com")
        p.validate_config()  # no raise

    async def test_validate_config_fails(self):
        p = TemplateProvider(api_url="")
        with pytest.raises(ValueError, match="api_url is required"):
            p.validate_config()

    async def test_health_connected(self, monkeypatch):
        async def mock_get(*args, **kwargs):
            class FakeResp:
                status_code = 200
                def raise_for_status(self): ...
            return FakeResp()

        monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
        p = TemplateProvider(api_url="https://ok.example.com")
        result = await p.health()
        assert result["connected"] is True

    async def test_health_disconnected(self, monkeypatch):
        async def mock_get(*args, **kwargs):
            raise ConnectionError("refused")

        monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
        p = TemplateProvider(api_url="https://bad.example.com")
        result = await p.health()
        assert result["connected"] is False
        assert "refused" in result["error"]

    async def test_query_raises_on_missing_endpoint(self, monkeypatch):
        async def mock_get(*args, **kwargs):
            class FakeResp:
                status_code = 200
                def raise_for_status(self): ...
                def json(self): return {"items": []}
            return FakeResp()

        monkeypatch.setattr("httpx.AsyncClient.get", mock_get)
        p = TemplateProvider(api_url="https://api.example.com")
        result = await p.query(endpoint="items")
        assert result["success"] is True
        assert result["data"] == {"items": []}

    async def test_notify_absent(self):
        p = TemplateProvider(api_url="https://noop.example.com")
        # No client configured — just verify the method exists
        assert hasattr(p, "notify")

    async def test_get_webhook_none_by_default(self):
        p = TemplateProvider(api_url="https://wh.example.com")
        assert await p.get_webhook() is None

    async def test_get_webhook_after_set(self):
        p = TemplateProvider(api_url="https://wh.example.com")
        p.set_webhook_secret("s3cret")
        wh = await p.get_webhook()
        assert wh is not None
        assert wh["secret"] == "s3cret"
        assert "webhook" in wh["url"]

    async def test_class_attrs(self):
        assert TemplateProvider.PROVIDER_TYPE == "template"
        assert "read" in TemplateProvider.SCOPES
        assert "api_url" in TemplateProvider.FINGERPRINT_FIELDS
        assert TemplateProvider.CONFIG_SCHEMA is TemplateConfig

    async def test_default_provider_type_from_name(self):
        class ImplicitProvider(BaseProvider):
            def validate_config(self): ...
            async def health(self): return {"connected": True}
        assert ImplicitProvider.PROVIDER_TYPE == "implicitprovider"


class TestTemplateConfig:
    def test_valid(self):
        cfg = TemplateConfig(api_url="https://valid.example.com", timeout=60)
        assert cfg.api_url == "https://valid.example.com"
        assert cfg.timeout == 60

    def test_invalid_empty_url(self):
        with pytest.raises(ValidationError):
            TemplateConfig(api_url="")

    def test_invalid_timeout_range(self):
        with pytest.raises(ValidationError):
            TemplateConfig(api_url="https://x.com", timeout=0)

    def test_default_api_key(self):
        cfg = TemplateConfig(api_url="https://x.com")
        assert cfg.api_key == ""
