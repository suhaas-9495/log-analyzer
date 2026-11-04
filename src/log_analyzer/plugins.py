"""Tiny plugin registry used for parsers and detectors.

Built-ins register themselves with a decorator; third-party code is loaded from a
``"package.module:Factory"`` reference listed in the config (``parsers.plugins`` /
``detectors.plugins``), so extending the analyzer never requires editing this package.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class PluginError(RuntimeError):
    """A plugin reference could not be resolved."""


class Registry(Generic[T]):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._factories: dict[str, T] = {}

    def register(self, name: str) -> Callable[[T], T]:
        def decorator(factory: T) -> T:
            if name in self._factories:
                raise PluginError(f"{self.kind} {name!r} is already registered")
            self._factories[name] = factory
            return factory

        return decorator

    def get(self, name: str) -> T:
        try:
            return self._factories[name]
        except KeyError:
            known = ", ".join(sorted(self._factories)) or "none"
            raise PluginError(f"unknown {self.kind} {name!r} (available: {known})") from None

    def names(self) -> list[str]:
        return sorted(self._factories)


def load_reference(reference: str) -> object:
    """Import ``"package.module:attribute"`` and return the attribute."""
    module_name, sep, attribute = reference.partition(":")
    if not sep or not module_name or not attribute:
        raise PluginError(f"invalid plugin reference {reference!r} (expected 'module:Name')")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise PluginError(f"cannot import plugin module {module_name!r}: {exc}") from exc
    try:
        return getattr(module, attribute)
    except AttributeError:
        raise PluginError(f"plugin module {module_name!r} has no {attribute!r}") from None
