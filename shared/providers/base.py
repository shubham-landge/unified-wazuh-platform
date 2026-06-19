from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel


class BaseProvider(ABC):
    """Abstract base for every connector/provider in the platform.

    Subclasses must declare metadata class-vars and implement
    ``validate_config()`` and ``health()``.  Optional capabilities
    (query, notify, webhook) should be mixed in by the concrete provider.
    """

    PROVIDER_TYPE: ClassVar[str] = ""
    SCOPES: ClassVar[list[str]] = []
    FINGERPRINT_FIELDS: ClassVar[list[str]] = []
    CONFIG_SCHEMA: ClassVar[type[BaseModel] | None] = None

    # ── required ──────────────────────────────────────────────────────────

    @abstractmethod
    def validate_config(self) -> None:
        """Raise :exc:`ValidationError` when the provider's config is invalid.

        Called once at construction / registration time so misconfigured
        providers fail fast.
        """
        ...

    @abstractmethod
    async def health(self) -> dict:
        """Return a connectivity / liveness status dictionary.

        Every ``health()`` response **must** include at least a ``"connected"``
        boolean key.  Example::

            {"connected": True, "latency_ms": 42}
        """
        ...

    # ── optional capabilities ─────────────────────────────────────────────

    async def query(self, **kwargs: Any) -> dict:
        """Query the provider for data.

        Implementations should raise :exc:`NotImplementedError` if the
        provider does not support querying.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support query()")

    async def notify(self, **kwargs: Any) -> dict:
        """Send a notification / event through this provider.

        Implementations should raise :exc:`NotImplementedError` if the
        provider does not support sending notifications.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support notify()")

    async def get_webhook(self) -> dict | None:
        """Return webhook metadata (URL, secret, events) if the provider
        exposes an incoming webhook endpoint.

        Returns ``None`` when the provider has no webhook.
        """
        return None

    # ── helpers ───────────────────────────────────────────────────────────

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.PROVIDER_TYPE:
            cls.PROVIDER_TYPE = cls.__name__.lower()
