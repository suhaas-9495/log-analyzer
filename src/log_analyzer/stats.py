"""Small, dependency-free statistics helpers used by the detectors."""

from __future__ import annotations

from collections.abc import Sequence


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median of empty sequence")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile, ``pct`` in [0, 100]."""
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    rank = max(1, round(pct / 100.0 * len(ordered) + 0.5 - 1e-9))
    return ordered[min(rank, len(ordered)) - 1]


def kendall_tau(values: Sequence[float]) -> float:
    """Kendall rank correlation between sample order and value (-1..1).

    A robust monotonic-trend statistic: +1 means every later sample is larger than every
    earlier one. Unlike a mean ratio it is insensitive to single outliers, which is what
    separates a *gradual* degradation from random slow requests. O(n^2), n is small.
    """
    n = len(values)
    if n < 2:
        return 0.0
    concordant = discordant = 0
    for i in range(n - 1):
        vi = values[i]
        for j in range(i + 1, n):
            vj = values[j]
            if vj > vi:
                concordant += 1
            elif vj < vi:
                discordant += 1
    pairs = n * (n - 1) / 2
    return (concordant - discordant) / pairs


def kendall_z(tau: float, n: int) -> float:
    """Mann-Kendall z-score of ``tau`` for ``n`` samples under the no-trend hypothesis.

    Using significance instead of a fixed tau lets a short but perfectly monotonic series
    (5 samples, 5 minutes apart) count as a trend, while a short *noisy* run does not.
    """
    if n < 3:
        return 0.0
    variance = 2.0 * (2 * n + 5) / (9.0 * n * (n - 1))
    return tau / variance**0.5


def slope(points: Sequence[tuple[float, float]]) -> float:
    """Least-squares slope of (x, y) points; 0 if undefined."""
    n = len(points)
    if n < 2:
        return 0.0
    mean_x = sum(p[0] for p in points) / n
    mean_y = sum(p[1] for p in points) / n
    var_x = sum((p[0] - mean_x) ** 2 for p in points)
    if var_x == 0:
        return 0.0
    cov = sum((p[0] - mean_x) * (p[1] - mean_y) for p in points)
    return cov / var_x
