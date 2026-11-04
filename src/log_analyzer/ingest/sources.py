"""Input sources: files (plain or gzip), several files merged by time, and live stdin."""

from __future__ import annotations

import gzip
import heapq
import io
import queue
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TextIO

from log_analyzer.models import LogEvent

_EOF = object()


def open_text(path: str | Path) -> TextIO:
    """Open a log file for reading; ``.gz`` files are decompressed transparently.

    Undecodable bytes are replaced rather than aborting the whole analysis.
    """
    p = Path(path)
    if p.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(p, "rb"), encoding="utf-8", errors="replace")
    return p.open(encoding="utf-8", errors="replace")


def merged_events(paths: list[str], parse: Callable[[str], LogEvent | None]) -> Iterator[LogEvent]:
    """Yield events from several files in timestamp order (each file assumed ordered).

    Logs from different services usually live in different files; merging them by event
    time is what makes cross-service correlation possible.
    """

    def stream(index: int, path: str) -> Iterator[tuple[float, int, int, LogEvent]]:
        seq = 0
        with open_text(path) as handle:
            for line in handle:
                event = parse(line)
                if event is None:
                    continue
                seq += 1
                yield event.ts, index, seq, event

    streams = [stream(i, p) for i, p in enumerate(paths)]
    for _ts, _index, _seq, event in heapq.merge(*streams):
        yield event


class LineReader:
    """Reads a text stream on a background thread so the consumer can time out.

    Lets the live console refresh its dashboard (and close idle incidents) while
    ``tail -f`` is quiet. A bounded queue gives back-pressure if analysis falls behind.
    """

    def __init__(self, stream: TextIO, max_buffered: int = 10_000) -> None:
        self._queue: queue.Queue[object] = queue.Queue(maxsize=max_buffered)
        self._thread = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        self._thread.start()

    def _pump(self, stream: TextIO) -> None:
        try:
            for line in stream:
                self._queue.put(line)
        finally:
            self._queue.put(_EOF)

    def lines(self, timeout: float) -> Iterator[str | None]:
        """Yield lines; yield ``None`` whenever ``timeout`` passes without input."""
        while True:
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                yield None
                continue
            if item is _EOF:
                return
            if isinstance(item, str):
                yield item
