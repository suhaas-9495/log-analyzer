"""Service topology: known services, aliases and the static dependency graph.

The directory answers two questions that correlation depends on:

* *Is this token a service?* Only configured services, their aliases and services that
  have actually emitted logs count. This is what stops garbled values such as
  ``Connection timeout to file_007f1c1f.txt`` from inventing fake dependencies.
* *Which services does this message mention?* ``"Payment provider unavailable"`` names
  ``payment-provider`` once hyphens and case are normalised.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Iterable

from log_analyzer.config.schema import AnalyzerConfig

_NON_WORD = re.compile(r"[\s_\-]+")


def _normalise(text: str) -> str:
    return _NON_WORD.sub(" ", text.lower()).strip()


class ServiceDirectory:
    def __init__(self, config: AnalyzerConfig, max_observed: int = 10_000) -> None:
        self._dependencies: dict[str, frozenset[str]] = {}
        self._names: dict[str, str] = {}  # normalised name/alias -> canonical service
        for svc in config.services:
            self._dependencies[svc.name] = frozenset(svc.dependencies)
            self._add_name(svc.name, svc.name)
            for alias in svc.aliases:
                self._add_name(alias, svc.name)
            for dep in svc.dependencies:
                self._add_name(dep, dep)
        for rule in config.patterns:
            if rule.target:
                self._add_name(rule.target, rule.target)
        self._observed: OrderedDict[str, None] = OrderedDict()
        self._max_observed = max_observed
        self._mention_regex: re.Pattern[str] | None = None
        self._dirty = True

    # ------------------------------------------------------------------ registration
    def _add_name(self, name: str, service: str) -> None:
        key = _normalise(name)
        if key and key not in self._names:
            self._names[key] = service
            self._dirty = True

    def observe(self, service: str) -> None:
        """Record a service seen emitting logs (bounded LRU)."""
        if service in self._observed:
            self._observed.move_to_end(service)
            return
        self._observed[service] = None
        if len(self._observed) > self._max_observed:
            self._observed.popitem(last=False)
        self._add_name(service, service)

    # ------------------------------------------------------------------- queries
    def resolve(self, token: str | None) -> str | None:
        """Canonical service for ``token`` if it names a known service, else ``None``."""
        if not token:
            return None
        return self._names.get(_normalise(token))

    def mentions(self, text: str) -> set[str]:
        """Services named (by name or alias) anywhere in ``text``."""
        regex = self._regex()
        if regex is None:
            return set()
        return {self._names[m] for m in regex.findall(_normalise(text))}

    def plausible(self, service: str, dependency: str) -> bool:
        """Can ``service`` depend on ``dependency``?

        If the service's dependencies are configured, a log line claiming a failed call
        to anything else is not trusted as correlation evidence (random noise in the
        sample data names arbitrary services, e.g. order-service "timing out" on the
        API gateway that calls it). Services without configured dependencies are
        unknown territory, so the logs are trusted.
        """
        configured = self._dependencies.get(service)
        return not configured or dependency in configured

    def depends_on(self, service: str, dependency: str) -> bool:
        return dependency in self._dependencies.get(service, ())

    def linked(self, a: str, b: str) -> bool:
        return self.depends_on(a, b) or self.depends_on(b, a)

    def dependencies(self, service: str) -> frozenset[str]:
        return self._dependencies.get(service, frozenset())

    def static_edges(self, nodes: Iterable[str]) -> set[tuple[str, str]]:
        node_set = set(nodes)
        return {
            (src, dst)
            for src in node_set
            for dst in self._dependencies.get(src, ())
            if dst in node_set
        }

    def _regex(self) -> re.Pattern[str] | None:
        if self._dirty:
            names = sorted(self._names, key=len, reverse=True)  # longest alias wins
            self._mention_regex = (
                re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\b")
                if names
                else None
            )
            self._dirty = False
        return self._mention_regex
