from .base import BaseCollector


class CollectorRegistry:
    def __init__(self):
        self._collectors: dict[str, type[BaseCollector]] = {}

    def register(self, collector_class: type[BaseCollector]):
        if not issubclass(collector_class, BaseCollector):
            raise TypeError("collector_class must inherit BaseCollector")
        key = collector_class.source_type.lower()
        if key in self._collectors:
            raise ValueError(f"collector type already registered: {key}")
        self._collectors[key] = collector_class
        return collector_class

    def get(self, source_type: str) -> type[BaseCollector]:
        try:
            return self._collectors[source_type.lower()]
        except KeyError as exc:
            raise KeyError(f"unknown collector type: {source_type}") from exc

    def create(self, source_type: str, **kwargs) -> BaseCollector:
        return self.get(source_type)(**kwargs)

    def create_for_source(self, source) -> BaseCollector:
        return self.get(source.SourceType).from_source(source)

    def registered_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._collectors))


collector_registry = CollectorRegistry()
