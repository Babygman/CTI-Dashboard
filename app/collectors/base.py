from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from typing import Any

from .normalizer import NormalizedItem, normalize_item


class CollectorError(RuntimeError):
    """Raised when a collector cannot fetch or parse its source."""


class BaseCollector(ABC):
    """Provider-neutral collector contract.

    Network collectors must apply timeout_seconds to every external request.
    The local demo collector deliberately performs no network activity.
    """

    source_name: str
    source_type: str

    def __init__(self, timeout_seconds: int = 30):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds

    @property
    def source_identity(self) -> dict[str, str]:
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
        }

    @abstractmethod
    def fetch(self) -> Any:
        """Fetch raw provider content.

        Implementations should translate provider/transport failures to
        CollectorError and must use self.timeout_seconds.
        """

    def parse(self, payload: Any) -> Iterable[Mapping[str, Any]]:
        """Parse a fetched payload into raw item mappings."""
        if not isinstance(payload, list):
            raise CollectorError("collector payload must be a list of items")
        for item in payload:
            yield item

    def normalize(self, item: Mapping[str, Any]) -> NormalizedItem:
        """Convert one parsed item to the shared normalized representation."""
        if not isinstance(item, Mapping):
            raise ValueError("parsed collector item must be a mapping")
        return normalize_item(item, source_name=self.source_name)
