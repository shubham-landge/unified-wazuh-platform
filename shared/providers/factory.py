import logging
from typing import Any

from pydantic import BaseModel, ValidationError

from shared.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class ProviderRegistry:
    """Registry that maps ``PROVIDER_TYPE`` → provider class.

    Typical usage::

        registry = ProviderRegistry()
        registry.register(TemplateProvider)
        provider = registry.get_provider("template", cfg={...})
    """

    def __init__(self) -> None:
        self._providers: dict[str, type[BaseProvider]] = {}

    def register(self, cls: type[BaseProvider]) -> None:
        """Register a provider class under ``cls.PROVIDER_TYPE``.

        Raises :exc:`ValueError` if a provider with the same type string
        is already registered.
        """
        provider_type = cls.PROVIDER_TYPE
        if not provider_type:
            raise ValueError(
                f"{cls.__name__}.PROVIDER_TYPE is empty — cannot register"
            )
        if provider_type in self._providers:
            raise ValueError(
                f"Provider type {provider_type!r} already registered "
                f"(existing: {self._providers[provider_type].__name__})"
            )
        self._providers[provider_type] = cls
        logger.debug("Registered provider type %r → %s", provider_type, cls.__name__)

    def get_provider(
        self,
        provider_type: str,
        cfg: dict[str, Any] | None = None,
    ) -> BaseProvider:
        """Instantiate a registered provider by type string.

        *cfg* is passed as ``**kwargs`` to the constructor.  If the
        provider declares a ``CONFIG_SCHEMA`` the raw *cfg* dict is
        validated against it before construction.
        """
        cls = self._providers.get(provider_type)
        if cls is None:
            raise KeyError(
                f"Unknown provider type {provider_type!r}. "
                f"Registered: {list(self._providers)}"
            )

        cfg = cfg or {}

        # Validate config against schema when the provider declares one.
        if cls.CONFIG_SCHEMA is not None:
            cls.CONFIG_SCHEMA.model_validate(cfg)

        instance = cls(**cfg)
        instance.validate_config()
        return instance

    @property
    def registered_types(self) -> list[str]:
        return list(self._providers)

    def __contains__(self, provider_type: str) -> bool:
        return provider_type in self._providers
