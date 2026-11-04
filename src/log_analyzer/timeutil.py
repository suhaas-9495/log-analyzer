"""Time parsing and formatting helpers.

All internal timestamps are float epoch seconds (UTC). Floats keep window arithmetic
cheap on the hot path; conversion to ``datetime`` only happens at the edges.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, tzinfo

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|sec|secs|m|min|mins|h|hr|hrs|d)?\s*$", re.I)
_UNIT_SECONDS = {
    None: 1.0,
    "ms": 0.001,
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "m": 60.0,
    "min": 60.0,
    "mins": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hrs": 3600.0,
    "d": 86400.0,
}
_FRACTION_RE = re.compile(r"[.,](\d+)")


def parse_timestamp(text: str, default_tz: tzinfo = UTC) -> float:
    """Parse an ISO-8601-like timestamp into epoch seconds.

    Accepts ``T`` or space separators, ``,`` or ``.`` fractional separators, any number
    of fractional digits (truncated to microseconds), ``Z`` or numeric offsets.
    Naive timestamps are interpreted in ``default_tz``.

    Raises:
        ValueError: if the text is not a valid timestamp.
    """
    candidate = text.strip()
    try:  # fast path: the C implementation handles almost every real-world variant
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        match = _FRACTION_RE.search(candidate, 19)
        if match is None:
            raise
        digits = match.group(1)[:6].ljust(6, "0")
        dt = datetime.fromisoformat(
            f"{candidate[: match.start()]}.{digits}{candidate[match.end() :]}"
        )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.timestamp()


def format_iso(ts: float) -> str:
    """Format epoch seconds as ``YYYY-MM-DDTHH:MM:SSZ`` (the alert format in the spec)."""
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_datetime(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S")


def format_clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%H:%M:%S")


def format_date_compact(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y%m%d")


def format_duration(seconds: float) -> str:
    """Human friendly duration: ``4m 37s``, ``1h 02m``, ``12s``."""
    total = max(0, round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def parse_duration(value: str | float) -> float:
    """Parse ``"5m"``, ``"300s"``, ``"1.5h"``, ``"250ms"`` or a bare number of seconds.

    Raises:
        ValueError: on malformed input or a non-positive duration.
    """
    if isinstance(value, bool):
        raise ValueError(f"invalid duration: {value!r}")
    if isinstance(value, int | float):
        seconds = float(value)
    else:
        match = _DURATION_RE.match(value)
        if match is None:
            raise ValueError(f"invalid duration: {value!r} (examples: 30s, 5m, 1h)")
        unit = match.group(2).lower() if match.group(2) else None
        seconds = float(match.group(1)) * _UNIT_SECONDS[unit]
    if seconds <= 0:
        raise ValueError(f"duration must be positive: {value!r}")
    return seconds
